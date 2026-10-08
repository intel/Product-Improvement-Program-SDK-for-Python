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

import asyncio
import json

from aiofile import AIOFile

from iaspython._core.logger import logger as log
from iaspython._core.session import TelemetrySessionBase


class TelemetrySession(TelemetrySessionBase):
    async def attach_file(self, name, filepath, ts=None, segments=None, guid=None, compress=False):
        """Attaches a file to this session. Must be awaited.

        Takes the same arguments and returns the same GUID as the synchronous
        TelemetrySession.attach_file.

        Runs on a worker thread: storing an attachment compresses and copies a
        potentially crash-dump-sized file, which would hold the event loop.

        Cancelling does not stop the work, because a thread cannot be
        interrupted from outside. Left unshielded, the caller would believe
        the attachment never happened and be free to flush, racing a worker
        that still appends the story and stores the file.

        So the worker is shielded and waited for before the cancellation is
        passed on. The caller still sees CancelledError and still cannot rely
        on the attachment having been rejected, but the work has finished
        rather than being in flight. attach() and the async uploader do the
        same.
        """
        stored = asyncio.ensure_future(
            asyncio.to_thread(super().attach_file, name, filepath, ts, segments, guid, compress)
        )
        try:
            return await asyncio.shield(stored)
        except BaseException:
            # BaseException, not Exception: CancelledError is not an
            # Exception, and cancellation is what this is here for.
            #
            # gather with return_exceptions waits for the worker without
            # raising what it ended up doing -- the caller must see its own
            # cancellation -- while still retrieving any worker failure, which
            # asyncio would otherwise report as never retrieved.
            await asyncio.gather(stored, return_exceptions=True)
            raise

    async def attach(self, name, payload, ts=None, segments=None, guid=None, compress=False):
        """Attaches data to this session. Must be awaited.

        Args:
            name (str): Attach event name
            payload (str, dict, bytes or bytearray): Data to attach
            ts (datetime or int, optional): Timestamp of event, if not provided, current time will be used
            segments (dict, optional): Optional metadata
            guid (str): GUID of attach, which will be generated if not provided
            compress (bool, optional): Compress the data before storing it, false by default.
                                       Decides the attachment's content encoding, the "ce" of
                                       its story.

        Returns:
            str: The GUID of the attachment.

        Raises:
            TelemetrySessionClosed: If the session was closed.
            TypeError: If an argument is of the wrong type.
            ValueError: If an argument is not valid, or the GUID is already in use.
            OSError: If the attachment file could not be written.
        """  # noqa: DOC503

        if type(payload) is dict:
            payload = json.dumps(payload)
            open_flag = "w"
        elif type(payload) is str:
            open_flag = "w"
        elif type(payload) is bytearray:
            payload = bytes(payload)
            open_flag = "wb"
        elif type(payload) is bytes:
            open_flag = "wb"
        else:
            raise TypeError("payload must be bytes, bytearray, str or dict")
        if len(payload) == 0:
            log.error("payload size is zero")
            raise ValueError("payload size is zero")

        # Written straight into the attachments folder under its GUID, where
        # attach_file() has to store it anyway. Claimed before the write, not
        # just in attach_file: writing first would already have clobbered a
        # stored attachment of the same GUID.
        guid = self._make_guid(guid)
        path = self.store.claim(guid)

        try:
            async with AIOFile(path, open_flag) as f:
                await f.write(payload)
        except OSError as e:
            log.error('Could not create attachment file "{}", OSError: {}'.format(path, e))
            self.store.release(path)
            raise
        except BaseException:
            # BaseException, not Exception: this is an await, so the caller can
            # cancel it, and CancelledError is not an Exception. A cancelled
            # write would otherwise strand the claim, and the next use of that
            # GUID would fail as a collision.
            self.store.release(path)
            raise
        log.info("created attachment file {}".format(path))

        # attach_file works on a worker thread that cannot be cancelled once
        # started, and may have stored the attachment and appended its story.
        # Releasing the claim then would delete content a story refers to, so
        # the task is shielded and its outcome awaited first.
        stored = asyncio.ensure_future(self.attach_file(name, path, ts, segments, guid, compress))
        try:
            return await asyncio.shield(stored)
        except BaseException:
            try:
                await stored
            except BaseException:
                # It failed too, so no story refers to the file and the claim
                # can go. The caller must see attach_file's rejection, or
                # their own cancellation, not a cleanup problem on top.
                self.store.release(path)
            raise
