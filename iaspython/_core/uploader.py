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

import os
import platform
from collections import namedtuple

from iaspython._core import utils
from iaspython._core.logger import logger as log
from iaspython._core.session import CONTENT_ENCODING_RAW
from iaspython._core.skr import (
    ATTACH_CONTENT_TYPE,
    EVENTS_CONTENT_TYPE,
    SKR_SOURCE_NAME,
    AttachmentFile,
    build_events_content,
    build_skr_record_body,
    build_zip_file,
    remove_staged_content,
    sha256_hex,
    uuid7,
)

# One SKR record, built and ready to be posted and uploaded.
#
# body:         the JSON body for POST /records
# events_bytes: zstd-compressed NDJSON events content
# zip_path:     staged ZIP of the attachment files, streamed to the cloud from
#               disk, or None if the record has no attachments
# attach_files: the AttachmentFiles packaged into the ZIP
PreparedRecord = namedtuple("PreparedRecord", ["body", "events_bytes", "zip_path", "attach_files"])


def _original_name(entry):
    """The attachment's source filename, for the manifest's orig_file_name.

    "_p" is the basename of the file the application handed over. attach() has
    no such file -- it writes the payload into the store under the GUID and
    hands that path to attach_file() -- so there "_p" comes back as the GUID
    itself. That would only repeat upload_file_name, so the attachment's name
    is used instead.
    """
    original = entry.get("_p", "")
    if not original or original == entry.get("g"):
        return entry.get("n", "")
    return original


class SkrUploaderBase:
    """Everything about building an SKR record that does not touch the network.

    The sync and async uploaders subclass this and add only the three steps
    that have to differ: upload_record, _post_record and _put_content_by_type.
    """

    def __init__(self, sdk_version, ias_telemetry_id, http_client, telemetry_url, store):
        self.sdk_version = sdk_version
        self.ias_telemetry_id = ias_telemetry_id
        self.http_client = http_client
        self.store = store
        # telemetry_url is the policy authority, overridden by CollectorUrl.
        self.records_url = utils.join_url(telemetry_url, "records")
        self.useragent = SKR_SOURCE_NAME + "/" + sdk_version + ";" + platform.system()

    def _build_record(self, payload):
        """Turns one telemetry payload into a record ready for upload.

        Each attachment story's GUID is that attachment's filename in the
        attachments folder, and its entry name in the ZIP. The story's other
        fields travel with it because the package has to describe itself too,
        in a manifest the cloud reads without the events record.

        Args:
            payload (dict): The stored payload to turn into a record.

        Returns:
            PreparedRecord|None: None if the payload holds nothing to upload.
            The record owns a staged ZIP on disk, which must be released with
            discard_staged_zip once the upload is done with it.

        Raises:
            OSError: If the staged ZIP could not be built. It is removed
                first, so nothing is left behind.
        """  # noqa: DOC503
        events_bytes, attachments = build_events_content(payload)
        if not events_bytes:
            return None

        record_uuid = uuid7()

        attach_files = self._collect_attachment_files(attachments)
        staged_zip = None
        attach_meta = None
        if attach_files:
            staged_zip = build_zip_file(attach_files, self.store.zip_staging_path(record_uuid), payload["tid"])
            attach_meta = {
                "hash": staged_zip.digest,
                "size": staged_zip.size,
                "filename": "{}_{}.zip".format(record_uuid, ATTACH_CONTENT_TYPE),
            }

        events_meta = {
            "hash": sha256_hex(events_bytes),
            "size": len(events_bytes),
            "filename": "{}_{}.ndjson".format(record_uuid, EVENTS_CONTENT_TYPE),
        }
        try:
            body = build_skr_record_body(
                self.sdk_version, self.ias_telemetry_id, payload["did"], record_uuid, events_meta, attach_meta
            )
        except Exception:
            # No record to hand the staged zip over to.
            self.discard_staged_zip(staged_zip.path if staged_zip else None)
            raise
        return PreparedRecord(body, events_bytes, staged_zip.path if staged_zip else None, attach_files)

    def discard_staged_zip(self, zip_path):
        """Releases the staged attachment ZIP a record was built with.

        The attachment files it was built from are untouched: they are only
        purged once the record they belong to has been accepted.
        """
        remove_staged_content(zip_path)

    def _collect_attachment_files(self, attachments):
        """Resolves a payload's attachment stories to files on disk.

        A referenced file can legitimately be gone: rawFilesAge reaps
        attachments far sooner than the payload itself (10 days against 90, by
        default). The record is still uploaded, carrying the attachment's
        metadata without its content, rather than stranding every event story
        behind a file that will never return.

        Args:
            attachments (list): The attachment story entries the payload
                carries, each naming its GUID in "g".

        Returns:
            list: AttachmentFiles, one per GUID, in payload order.
        """
        files = []
        seen = set()
        for entry in attachments:
            guid = entry["g"]
            if guid in seen:
                continue
            seen.add(guid)
            path = self.store.path_for(guid)
            if os.path.isfile(path):
                files.append(
                    AttachmentFile(
                        guid=guid,
                        path=path,
                        name=_original_name(entry),
                        size=entry.get("sz", 0),
                        encoding=entry.get("ce", CONTENT_ENCODING_RAW),
                    )
                )
            else:
                log.warning(
                    "attachment {} is missing from {}; uploading the record with its metadata "
                    "but without its content".format(guid, self.store.directory)
                )
        return files

    def _delete_attachment_files(self, attach_files):
        """Purges the attachment files that are now packaged into the record."""
        for f in attach_files:
            try:
                os.remove(f.path)
            except OSError as e:
                log.error("failed to delete attachment file {}: {}".format(f.path, e))
