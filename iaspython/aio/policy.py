# Copyright (c) 2026 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import uuid
from json.decoder import JSONDecodeError

from aiofile import AIOFile

from iaspython._core.logger import logger as log
from iaspython._core.policy import PolicyBase, response_etag
from iaspython._core.skr import response_data
from iaspython._core.store import STAGING_SUFFIX, create_private, makedirs_private, remove_quietly
from iaspython._core.utils import STATUS_NOT_MODIFIED

# policy documentation:
#   RFD-0031, frameworks.telemetry.skylight-ridge.rfd


class Policy(PolicyBase):
    """Sequences the policy I/O. Every decision lives in PolicyBase, so this
    class and its sync twin differ only in how they read and write files."""

    async def load_policy(self):
        if not self.is_expired():
            log.info("valid policy in effect, no need to download a new telemetry policy")
            return True

        if not self.should_download():
            log.info("the current policy does not apply to this device, not downloading a new one yet")
            return False

        # Kept in scope for the 304 branch below, which refreshes this very
        # document rather than downloading it again.
        cached = None
        if os.path.exists(self.local_policy_file):
            log.info("read policy document from the local file {}".format(self.local_policy_file))
            cached = await self._read_file(self.local_policy_file)
            if cached is None:
                # Unreadable, not unusable: nothing here says the document is
                # bad, and accept_cached would read the missing content as an
                # unusable policy and delete what may be this device's only
                # one. Only a document actually read is worth discarding.
                log.warning("could not read the cached policy, leaving it in place")
            elif self.accept_cached(cached):
                return True
            elif not self.should_download():
                # The cached document is current, it just is not for us.
                return False

        url = self.policy_request_url()
        log.info("download policy document from the URL {}".format(url))
        success, resp, headers, status = await self.http_client.get(url, headers=self.request_headers())
        if not success:
            log.error("Could not download the policy")
            return False

        if status == STATUS_NOT_MODIFIED:
            # The document on disk is still current, and `cached` is the dict
            # it was just read from.
            in_effect = self.accept_not_modified(cached)
            if cached is not None:
                # Re-read rather than trust the copy from before the
                # request: the other process of this app may have cached a
                # newer document while this one was in flight. See
                # refresh_would_lose_a_newer_policy.
                on_disk = await self._read_file(self.local_policy_file)
                if self.refresh_would_lose_a_newer_policy(on_disk):
                    log.info("a newer policy was cached while this one was being revalidated, keeping it")
                else:
                    await self._write_file(self.local_policy_file, cached)
            return in_effect

        doc = response_data(resp)
        if doc is None:
            # A 200 that is not this service's envelope. Treated as a failed
            # fetch rather than a bad policy: nothing was learned about the
            # document, so there is nothing to cache or discard.
            log.error("the policy response has no data section")
            return False

        if not self.accept_downloaded(doc, response_etag(headers)):
            return False
        # Cached even when it does not apply here, so the same answer is not
        # re-fetched on every flush until it expires.
        await self._write_file(self.local_policy_file, doc)
        return not self.is_expired()

    async def _read_file(self, path):
        """Reads and parses the cached document.

        Args:
            path (str): The cache file to read.

        Returns:
            dict|None: None when the bytes never arrived, so nothing is known
            about the document and the file must be left alone. An empty dict
            when the bytes arrived and are not a policy, which is a verdict on
            the file and grounds for deleting it. Everything that is not an
            I/O failure takes the second answer, since only that leads to the
            file being replaced.
        """
        log.info("read json document from the file {}".format(path))
        try:
            async with AIOFile(path, "r") as f:
                s = await f.read()
        except IOError as e:
            log.error("I/O error: {}".format(e))
            return None
        except ValueError as e:
            # UnicodeDecodeError is a ValueError, not an IOError, so it would
            # otherwise land in the host application's flush(). The bytes did
            # arrive, so this is the same verdict as unparseable JSON.
            log.error("the cached policy is not decodable text: {}".format(e))
            return {}
        try:
            doc = json.loads(s)
            log.debug("content=\n{}".format(json.dumps(doc, indent=2)))
        except JSONDecodeError as e:
            log.error("JSONDecodeError: {}".format(e))
            return {}
        if not isinstance(doc, dict):
            # Valid JSON and still not a document. `null` is the one that
            # matters: json.loads returns None, which is this method's "the
            # bytes never arrived" answer, so the file would be kept forever.
            log.error("the cached policy is a json {}, not an object".format(type(doc).__name__))
            return {}
        return doc

    async def _write_file(self, filepath, doc):
        """Replaces the cache file by renaming a finished copy onto it.

        os.replace is atomic, so a write killed part-way leaves the previous
        document intact rather than a truncated one -- which the next flush's
        accept_cached would discard, deleting what may be this device's only
        policy.

        The staged name carries a uuid because the other process of this app
        writes the same path, and two writers sharing a staging name would
        interleave their bytes and rename the mixture over the real file.
        """
        log.info("write json document to the file {}".format(filepath))
        log.debug("content=\n{}".format(json.dumps(doc, indent=2)))
        # None until the file exists, so a failure to create it does not send
        # the cleanup below after a path this call never owned.
        staged = None
        try:
            dirpath = os.path.dirname(os.path.abspath(filepath))
            # Tolerates an existing folder: the other process of this app
            # writes the same one, and a bare mkdir would make the loser drop
            # its cache write and re-download on the next flush. Owner-only;
            # see STORE_DIR_MODE.
            makedirs_private(dirpath)
            # Created owner-only before anything is written into it; AIOFile
            # alone would leave the staged document — and then, through the
            # rename below, the cached policy itself — at whatever the
            # machine's default is. See create_private.
            staged = create_private("{}.{}{}".format(filepath, uuid.uuid4(), STAGING_SUFFIX))
            async with AIOFile(staged, "w") as f:
                s = json.dumps(doc)
                await f.write(s)
            os.replace(staged, filepath)
            staged = None  # renamed away, so there is nothing left to clean up
        except IOError as e:
            log.error("I/O error: {}".format(e))
        except JSONDecodeError as e:
            log.error("JSONDecodeError: {}".format(e))
        finally:
            # A staged file nothing renamed is an unfinished write. Nothing
            # reads it, but they would accumulate one per failure.
            remove_quietly(staged, "staged policy file")
