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
import re
import uuid
from datetime import datetime
from threading import Lock

from iaspython._core import utils
from iaspython._core.exceptions import TelemetrySessionClosed
from iaspython._core.logger import logger as log
from iaspython._core.store import AttachmentStore, default_attachment_dir, remove_quietly

# The "ce" (content encoding) an attachment story reports.
#
# "zlib" names the bytes zlib's gzopen/gzwrite produce, which are a gzip
# stream rather than a raw zlib one. The label is a long-standing misnomer in
# the wire format, and the collector expects it, so do not "correct" it.
CONTENT_ENCODING_COMPRESSED = "zlib"
CONTENT_ENCODING_RAW = "raw"


class TelemetrySessionBase:
    """A named group of events and attachments within one telemetry stream."""

    def __init__(self, ts, app_id, default, name=None, segments=None, *, store=None):
        """The constructor of the TelemetrySession class.

        Args:
            ts (datetime or int): Start timestamp of session, if None is provided, the current time will be used
            app_id (str): GUID, the application's own id, as configured in TelemetryId.
            default (bool): Is this default session
            name (str, optional): Session name
            segments (dict, optional): Optional metadata
            store (AttachmentStore, optional): Where this session's attachments
                are put. Keyword only, and supplied by Telemetry, which owns
                the store. A session built directly gets one in the default
                location.

        Raises:
            TypeError: If an argument is of the wrong type.
            ValueError: If an argument is not valid.
        """

        self.name = ""
        self.app_id = app_id
        self.default = default
        # A reference to the store rather than a path: the folder belongs to
        # the store, and a session never knows where it is.
        self.store = store if store is not None else AttachmentStore(default_attachment_dir(app_id))
        self.active = True
        self.story_entry_timestamp_max = 0
        self.stories = []
        self.temp_files = []
        self.stories_lock = Lock()
        self.temp_files_lock = Lock()

        ts = self._get_timestamp(ts)
        if ts < 0:
            raise ValueError("timestamp must not be negative, got {}".format(ts))
        self.start_timestamp = ts

        if not default:
            if name:
                if not self._is_valid_story_entry_name(name):
                    log.error('Invalid session name "{}"'.format(name))
                    raise ValueError('Invalid session name "{}"'.format(name))
                self.name = name

            story = {"ts": ts, "t": "beg", "n": self.name}
            if segments:
                if not isinstance(segments, dict):
                    raise TypeError("segments parameter must be dict")
                story["d"] = segments
            self.stories.append(story)
        log.info("session created: name={} default={}".format(name, default))

    def record_event(self, name, count=1, asum=0, ts=None, segments=None):
        """Records an event.

        Args:
            name (str): Event name
            count (int, optional): Event count, if not provided, 1 will be used
            asum (float, optional): Event sum, if not provided, 0.0 will be used
            ts (datetime or int, optional): Timestamp of event, if not provided, current time will be used
            segments (dict, optional): Optional metadata

        Raises:
            TelemetrySessionClosed: If the session was closed.
            TypeError: If an argument is of the wrong type.
            ValueError: If an argument is not valid.
        """

        if not self.active:
            raise TelemetrySessionClosed("Could not record event, because telemetry session was closed")
        if not self._is_valid_story_entry_name(name):
            log.error('Invalid event name "{}"'.format(name))
            raise ValueError('Invalid event name "{}"'.format(name))
        count = int(count)
        if count < 1:
            raise ValueError("event count should be larger than 0")
        asum = float(asum)

        ts = self._get_timestamp(ts)
        if ts < self.start_timestamp:
            log.error('timestamp for event is too small "{}"'.format(ts))
            raise ValueError('timestamp for event is too small "{}"'.format(ts))
        elif ts > self.story_entry_timestamp_max:
            self.story_entry_timestamp_max = ts

        if segments and not isinstance(segments, dict):
            raise TypeError("segments argument must be a dict, got {}".format(type(segments)))
        story = {}
        story["ts"] = int(ts)
        story["t"] = "evt"
        story["n"] = name
        story["c"] = count
        story["s"] = asum
        if segments:
            story["d"] = segments
        with self.stories_lock:
            self.stories.append(story)
        log.info("event created: name={}".format(name))

    def attach_file(self, name, filepath, ts=None, segments=None, guid=None, compress=False):
        """Attaches a file.

        Args:
            name (str): Attach event name
            filepath (str): File path to the file
            ts (datetime or int, optional): Timestamp of event, if not provided, current time will be used
            segments (dict, optional): Optional metadata
            guid (str): GUID of attach, which will be generated if not provided
            compress (bool, optional): Compress the file before storing it.
                Decides the attachment's content encoding: the story's "ce" is
                written from it, so compression is asked for here rather than
                by declaring an encoding in segments.

        Returns:
            str: The GUID of the attachment.

        Raises:
            TelemetrySessionClosed: If the session was closed.
            TypeError: If an argument is of the wrong type.
            ValueError: If an argument is not valid, or the GUID is already in use.
        """  # noqa: DOC503

        if not self.active:
            log.error("telemetry session not active")
            raise TelemetrySessionClosed("Could not attach file, because telemetry session was closed")
        if compress is None:
            # "Not specified", as for ts and segments.
            compress = False
        if not isinstance(compress, bool):
            # Type-checked rather than used as a condition: the string "false"
            # passes a truthiness test, and this argument decides how the cloud
            # decodes the bytes. bool subclasses int, so True/False pass while
            # 0/1 do not, which is the intent.
            raise TypeError("compress must be bool, got {}".format(type(compress)))
        if segments and not isinstance(segments, dict):
            raise TypeError("segments argument must be a dict, got {}".format(type(segments)))
        # Copied, not filled in place. "e", "ce" and "sz" are only defaulted
        # below, so a caller who supplied one keeps it -- but writing into the
        # caller's own dict means a reused dict carries the first attachment's
        # generated values into the second, indistinguishable from the
        # caller's own. It also stops the story from sharing a dict the
        # application may still be rewriting.
        segments = dict(segments) if segments else {}
        guid = self._make_guid(guid)
        ts = self._get_timestamp(ts)
        if ts < self.start_timestamp:
            log.error('timestamp for event is too small "{}"'.format(ts))
            raise ValueError('timestamp for event is too small "{}"'.format(ts))
        elif ts > self.story_entry_timestamp_max:
            self.story_entry_timestamp_max = ts

        if not self._is_valid_story_entry_name(name):
            log.error("attachment name invalid")
            raise ValueError('Invalid attachment name "{}"'.format(name))
        if not os.path.exists(filepath):
            log.error("attachment file not found: {}".format(filepath))
            raise ValueError('attachment file not found "{}"'.format(filepath))

        filename, extension = os.path.splitext(filepath)
        extension = extension.lstrip(".").rstrip(".")

        # Captured before compression can point filepath at a temp file, so
        # this stays the caller's filename.
        original_name = os.path.basename(filepath)

        # Likewise captured before compression: "sz" describes the content the
        # caller handed over, not the size of the stored copy.
        filesize = os.path.getsize(filepath)
        if filesize <= 0:
            log.error("file size error".format(filesize))
            raise ValueError("file size error: size={}".format(filesize))

        # Claimed before compression, so a rejected attachment leaves no temp
        # behind. attach() claims the GUID itself and hands the path back here.
        claimed_path = None
        if not self.store.holds(filepath, guid):
            claimed_path = self.store.claim(guid)

        content_enc = CONTENT_ENCODING_RAW
        # A file we produced ourselves can be moved rather than copied.
        owns_file = False

        try:
            if compress:
                # Staged inside the store, so the gzip is created under the
                # store's own permissions. See AttachmentStore.staging_path.
                # The folders already exist; claim() made them.
                compressed_file = utils.compress_file(filepath, self.store.staging_path(guid))
                if compressed_file:
                    # Only now, so the story never advertises an encoding the
                    # stored bytes do not have: compress_file declines some
                    # inputs, such as an already-compressed .zip.
                    content_enc = CONTENT_ENCODING_COMPRESSED
                    filepath = compressed_file
                    owns_file = True
                else:
                    log.error("failed to compress file, attaching it as-is: {}".format(filepath))

            if "e" in segments:
                extension = segments["e"].lstrip(".").rstrip(".")

            segments["e"] = extension
            # Only defaulted, so a caller who put either in segments keeps it.
            # The story's own "ce" and "sz" always describe the attachment.
            segments.setdefault("ce", content_enc)
            segments.setdefault("sz", str(filesize))  # cloud expects string

            # Stored under the GUID, which is how the uploader finds it. The
            # rest of the metadata travels in the story entry below.
            stored_path = self.store.place(filepath, guid, move=owns_file)
        except Exception:
            if owns_file:
                # The gzip we made, which never reached the attachments folder.
                remove_quietly(filepath, "compressed attachment file")
            if claimed_path:
                self.store.release(claimed_path)
            raise

        story = {}
        story["ts"] = int(ts)
        story["t"] = "atc"
        story["n"] = name
        story["g"] = guid
        story["sz"] = filesize
        story["ce"] = content_enc
        story["e"] = extension
        # json.dumps escapes this, so a filename carrying a quote or backslash
        # survives the round trip.
        story["_p"] = original_name
        story["d"] = segments

        with self.stories_lock:
            self.stories.append(story)
        with self.temp_files_lock:
            self.temp_files.append(stored_path)

        log.info("attachment file created: name={} path={}".format(name, stored_path))
        return guid

    def end_session(self, ts=None):
        """Closes the session.

        Args:
            ts (datetime or int, optional): The session end timestamp, if not provided, current time will be used

        Raises:
            TelemetrySessionClosed: If the session was already closed.
            TypeError: If ts is of the wrong type.
            ValueError: If ts is not valid, or predates the session start or
                its latest event.
        """  # noqa: DOC201,DOC503

        if self.default:
            return
        if not self.active:
            raise TelemetrySessionClosed("Could not end telemetry session, because it was closed already")
        ts = self._get_timestamp(ts)
        if ts < self.start_timestamp or ts < self.story_entry_timestamp_max:
            raise ValueError(
                "Session end timestamp must not be smaller than session start time or any event timestamps in the session"
            )
        self.active = False
        self.stories.append({"t": "end", "ts": int(ts)})
        log.info("session ended: name={}".format(self.name))

    def delete_temp_files(self):
        """Deletes the attachment files this session stored.

        Failures are logged and swallowed: these live in the shared
        attachments folder, so another process of the same app can hold one
        open, which on Windows makes os.remove raise. This runs after a
        successful flush, and retention reaps whatever is left.
        """
        with self.temp_files_lock:
            for f in self.temp_files:
                remove_quietly(f, "attachment file")

    def _make_guid(self, guid):
        """Validates a caller-supplied attachment GUID, or generates one."""
        if not guid:
            return str(uuid.uuid4())
        # is_valid_guid also rejects anything that could escape the store when
        # the GUID is used as a filename.
        if not utils.is_valid_guid(guid):
            log.error("bad-formatted guid: {}".format(guid))
            raise ValueError("bad-formatted guid: {}".format(guid))
        return guid

    def _is_valid_story_entry_name(self, name):
        regex = re.compile("^[a-zA-Z][A-Za-z0-9_.-]*$")
        match = regex.match(name)
        return bool(match)

    def _get_timestamp(self, ts):
        if not ts:
            ts = datetime.now()
        if isinstance(ts, datetime):
            ts = ts.timestamp()
        return int(ts)
