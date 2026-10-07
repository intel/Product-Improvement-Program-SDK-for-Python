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

from iaspython._core.logger import logger as log
from iaspython._core.session import TelemetrySessionBase


class TelemetrySession(TelemetrySessionBase):
    def attach(self, name, payload, ts=None, segments=None, guid=None, compress=False):
        """Attaches data to this session.

        Args:
            name (str): Attach event name
            payload (str, dict, bytes or bytearray): Data to attach
            ts (datetime or int, optional): Timestamp of event, if not provided, current time will be used
            segments (dict, optional): Optional metadata
            guid (str): GUID of attach, if not provided, it will be generated
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
            try:
                with open(path, open_flag) as f:
                    f.write(payload)
            except OSError as e:
                log.error('Could not create attachment file "{}", OSError: {}'.format(path, e))
                raise
            log.info("created attachment file {}".format(path))
            return self.attach_file(name, path, ts, segments, guid, compress)
        except BaseException:
            # Nothing refers to the file now, so the claim goes with it. The
            # caller must see attach_file's rejection, not a cleanup problem
            # on top of it, so a failed delete is only logged.
            #
            # BaseException, so a KeyboardInterrupt does not strand the claim
            # either; the next use of that GUID would fail as a collision.
            self.store.release(path)
            raise
