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

from iaspython._core import utils
from iaspython._core.logger import logger as log
from iaspython._core.skr import (
    ATTACH_CONTENT_TYPE,
    EVENTS_CONTENT_TYPE,
    build_post_headers,
    resolve_upload_target,
)
from iaspython._core.uploader import SkrUploaderBase


class SkrUploader(SkrUploaderBase):
    def upload_record(self, payload):
        """Uploads one telemetry payload as a single SKR record.

        The attachment ZIP is uploaded before the events NDJSON that references
        it, and the attachment files are purged once they are part of the record.
        """
        try:
            record = self._build_record(payload)
        except Exception as e:
            # Building a record compresses, zips, hashes and writes temp
            # files, any of which can fail on a full or locked disk. Reported
            # as a failed upload rather than raised: the caller answers False
            # by saving the payload for a retry, and an exception by losing it.
            log.error("failed to build SKR record: {}".format(e))
            return False
        if record is None:
            # Nothing to upload, so nothing to retry either.
            return True

        try:
            success, resp = self._post_record(record.body)
            if not success:
                return False

            if record.zip_path and not self._put_file_by_type(resp, ATTACH_CONTENT_TYPE, record.zip_path):
                return False
            if not self._put_content_by_type(resp, EVENTS_CONTENT_TYPE, record.events_bytes):
                return False
        except Exception as e:
            # Uploading still touches the disk, and a transport can raise
            # something its own handler does not cover. Reported as a failed
            # upload for the same reason as the build stage above.
            log.error("failed to upload SKR record: {}".format(e))
            return False
        finally:
            # The staged zip is this record's alone, sent or not.
            self.discard_staged_zip(record.zip_path)

        self._delete_attachment_files(record.attach_files)
        return True

    def _post_record(self, body):
        headers = build_post_headers(self.useragent)
        content = json.dumps(body)
        log.info("posting SKR record to {}".format(utils.strip_url_secrets(self.records_url)))
        success, resp, _ = self.http_client.post(self.records_url, content, headers)
        if success:
            log.info("SKR record accepted")
        else:
            log.error("failed to post SKR record")
        return success, resp

    def _put_content_by_type(self, resp, content_type, data):
        return self._put_by_type(resp, content_type, data, len(data))

    def _put_file_by_type(self, resp, content_type, path):
        """Uploads staged content straight from disk.

        The open file is handed to the HTTP client rather than its contents,
        so an attachment ZIP is streamed rather than read into memory.
        """
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            return self._put_by_type(resp, content_type, f, size)

    def _put_by_type(self, resp, content_type, data, size):
        target = resolve_upload_target(resp, content_type, self.useragent)
        if not target:
            log.error("no accepted upload URL in SKR response for {}".format(content_type))
            return False
        url, headers = target
        log.info("uploading {} content ({} bytes)".format(content_type, size))
        success, _, _ = self.http_client.put(url, data, headers)
        if success:
            log.info("{} content uploaded successfully".format(content_type))
        else:
            log.error("failed to upload {} content".format(content_type))
        return success
