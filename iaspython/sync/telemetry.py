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

"""The blocking telemetry client."""

import json
import os
import time
import uuid
from datetime import datetime
from functools import wraps

from iaspython._core import utils
from iaspython._core.logger import logger as log
from iaspython._core.store import (
    STAGING_SUFFIX,
    create_private,
    makedirs_private,
    remove_quietly,
    restrict_to_owner,
)
from iaspython._core.telemetry import (
    TelemetryBase,
    is_claimed_name,
    is_uploadable_payload,
    remove_reaped_file,
)
from iaspython.sync.httpclient import HttpClient
from iaspython.sync.policy import Policy
from iaspython.sync.session import TelemetrySession
from iaspython.sync.uploader import SkrUploader

ZERO_UUID = "00000000-0000-0000-0000-000000000000"


class Telemetry(TelemetryBase):
    http_client: HttpClient
    policy: Policy
    default_session: TelemetrySession

    @wraps(TelemetryBase.__init__)
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            http_client_class=HttpClient,
            policy_class=Policy,
            session_class=TelemetrySession,
            **kwargs,
        )

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def attach(self, name, payload, ts=None, segments=None, guid=None, compress=False):
        """Attaches data to the default session.

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
            TelemetryClosed: If Telemetry was closed.
            TypeError: If an argument is of the wrong type.
            ValueError: If an argument is not valid, or the GUID is already in use.
        """  # noqa: DOC502

        self._check_initialized_or_raise()
        return self.default_session.attach(name, payload, ts, segments, guid, compress)

    def close(self):
        """Closes Telemetry and releases its HTTP session.

        Does not flush. Anything recorded and not yet flushed stays in memory
        and is lost, so call flush() first.

        Raises:
            TelemetryClosed: If Telemetry was already closed.
        """  # noqa: DOC502

        self._check_initialized_or_raise()
        self.http_client.close()
        self.initialized = False
        log.info("Telemetry deinitialized")

    def flush(self, flush_all=False):
        """Uploads recorded data to the cloud.

        If the policy is not valid or the client cannot connect to the cloud,
        data is saved to disk and retried by a later flush.

        Args:
            flush_all (bool, optional): If true, all sessions are closed and then all recorded data is uploaded
                                        If false, only data in closed session is uploaded

        Returns:
            bool: True if the data was uploaded, or the policy declined to
            take it; False if it was saved to disk. False is not an error.

        Raises:
            TelemetryClosed: If Telemetry was closed.
        """  # noqa: DOC502

        self._check_initialized_or_raise()
        if flush_all:
            self._close_sessions()

        # Carries the attachment stories too.
        payload = self._create_payload()

        # The policy's sampling selectors are evaluated against these, so they
        # must be known before the policy is loaded.
        self.policy.set_identity(payload["did"], payload["reports"][0]["uid"])
        # After set_identity, which invalidates the cached selector context,
        # and before load_policy, which sends it. The policy adds the backoff
        # when it builds the request; it is not known yet.
        self.policy.set_last_upload(self._read_lastupload())

        success = self.policy.load_policy()
        if not success:
            # Either the policy could not be fetched, or its global selector
            # excludes this device. Neither is permission to upload *yet*.
            log.warning("Can't upload to cloud at this moment. Save data to disk for now.")
            self._save_to_store(payload)
            self._clear_sessions(delete_temps=False)
            self._apply_retention_policy()
            return False

        if not self.policy.is_app_supported():
            log.info("the policy does not list this application's ID, discard data")
            self._clear_sessions(delete_temps=True)
            self._apply_retention_policy()
            return True

        # No endpoint at all is a decision, not a failure: the agent is
        # retired and retrying cannot change that, so the data is discarded.
        # Checked before the backoff, which implies something to back off to.
        if self.policy.is_retired():
            log.info("the policy provides no upload endpoint, discard data")
            self._clear_sessions(delete_temps=True)
            # Retention still has to run: anything an earlier flush queued can
            # never be uploaded now, and nothing else would clear it.
            self._apply_retention_policy()
            return True

        # An endpoint that is present but unusable is the opposite case and
        # must not reach the branch above: a later policy or SDK may be able to
        # act on it, so the data is kept.
        if not self.policy.can_upload():
            log.warning("the policy endpoint is not usable. Save data to disk for now.")
            self._save_to_store(payload)
            self._clear_sessions(delete_temps=False)
            self._apply_retention_policy()
            return False

        if not self._is_backoff_expired():
            log.warning("Can't upload to cloud at this moment. Save data to disk for now.")
            self._save_to_store(payload)
            self._clear_sessions(delete_temps=False)
            self._apply_retention_policy()
            return False

        uploader = SkrUploader(
            sdk_version=self.sdk_version,
            ias_telemetry_id=self.ias_telemetry_id,
            http_client=self.http_client,
            telemetry_url=self.policy.get_telemetry_url(),
            store=self.store,
        )

        # upload records that were saved previously
        uploaded_previous = self._upload_previous_records(uploader)

        # upload the current record
        success = uploader.upload_record(payload)
        if success or uploaded_previous:
            # The backoff counts uploads, not flushes: a queue that drained
            # while this payload failed is still an upload, and a stale stamp
            # would let the next flush straight through the gate.
            self._save_lastupload(datetime.now().timestamp())
        if success:
            self._clear_sessions(delete_temps=True)
            return True
        else:
            log.warning("Can't upload to cloud at this moment. Save data to disk for now.")
            self._save_to_store(payload)
            self._clear_sessions(delete_temps=False)
            self._apply_retention_policy()
            return False

    def _upload_previous_records(self, uploader):
        """Drains the store.

        Args:
            uploader (SkrUploader): The uploader to send each payload through.

        Returns:
            bool: True when at least one payload was uploaded. The caller
            stamps the backoff on this.

        Raises:
            BaseException: Re-raised after the claim is released, so a
                cancelled flush does not strand a claimed payload.
        """
        uploaded_any = False
        self._requeue_abandoned_claims()
        telemetries = self._read_telemetries_from_store()
        for payload, telemetry_path in telemetries:
            # Claimed before upload, so the other process of this app cannot
            # send the same events twice. See _claim_stored_telemetry.
            claimed_path = self._claim_stored_telemetry(telemetry_path)
            if claimed_path is None:
                continue
            # One stored payload must not stop the others: it is deleted only
            # once uploaded, so a payload that threw would be read again on
            # every flush and the queue behind it would never drain.
            try:
                uploaded = uploader.upload_record(payload)
            except Exception as e:
                log.error("failed to upload stored record {}: {}".format(telemetry_path, e))
                self._discard_stored_telemetry(claimed_path, "cannot be uploaded: {}".format(e))
                continue
            except BaseException:
                # A KeyboardInterrupt, which is not an Exception and misses
                # the branch above. The payload is untouched, so it goes back
                # in the queue rather than sitting claimed for the full grace
                # period with no flush able to see it.
                self._release_stored_telemetry(claimed_path)
                raise
            # upload_record purges the attachment files it packaged.
            if uploaded:
                uploaded_any = True
                remove_quietly(claimed_path, "uploaded telemetry")
            else:
                # Still good, just not uploaded. Back in the queue.
                self._release_stored_telemetry(claimed_path)
        return uploaded_any

    def _save_lastupload(self, lastupload):
        path = os.path.join(self._app_dir(), "lastupload")
        try:
            with open(path, "w") as f:
                f.write(json.dumps(str(int(lastupload))))
        except IOError as e:
            log.error("I/O error: {}".format(e))

    def _read_lastupload(self):
        """Returns when this device last uploaded, in epoch seconds, or 0.

        An unreadable stamp is reported as never, the same as an absent file.
        Raising instead would break flush() from the first corrupt byte
        onwards and stay broken, since nothing rewrites the file until an
        upload succeeds and no upload is attempted until it is read.
        """
        lastupload = 0
        path = os.path.join(self._app_dir(), "lastupload")
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    data = f.read()
                    lastupload = int(json.loads(data))
        except IOError as e:
            log.error("I/O error: {}".format(e))
        except (ValueError, TypeError, OverflowError) as e:
            # JSONDecodeError and int() on a non-number are both ValueError;
            # TypeError is int() on a null or list. OverflowError is int() on
            # the infinity json.loads makes of a number too large for a float,
            # such as 1e309, which parses fine and only fails at the int().
            log.error("the last upload stamp is unreadable, treating it as never: {}".format(e))
        return lastupload

    def _save_to_store(self, payload):
        telemetry_dir = self._telemetry_dir()
        staged = None

        try:
            # Tolerates an existing folder: the other process of this app
            # stores into the same one, and a bare mkdir would raise
            # FileExistsError on the loser of the race. Owner-only, since a
            # payload's filename announces a flush in progress.
            makedirs_private(telemetry_dir)
            path = os.path.join(telemetry_dir, payload["pid"] + ".json")

            # Written under a temporary name and renamed over the real one,
            # so nobody reads a half-written payload. That matters because
            # _read_telemetries_from_store *deletes* what it cannot parse, so
            # the other process of this app would destroy a partial file
            # rather than skip it. A rename within one directory is atomic on
            # both Windows and POSIX.
            #
            # See STAGING_SUFFIX for why the staging name does not end in
            # ".json". "pid" is a fresh uuid4, so two processes never pick the
            # same staging name.
            #
            # create_private, so the staged file -- and then, through the
            # rename, the payload itself -- is owner-only from the start. A
            # payload carries the device id and every event story.
            staged = create_private(path + STAGING_SUFFIX)
            with open(staged, "w") as f:
                f.write(json.dumps(payload))
            os.replace(staged, path)
            staged = None  # renamed away, so there is nothing left to clean up
            log.debug("telemetry data is saved to {}".format(path))

        except IOError as e:
            log.error("I/O error: {}".format(e))
            remove_quietly(staged, "staged telemetry file")
            raise
        except BaseException:
            # A KeyboardInterrupt mid-write, which is not an Exception. The
            # partial file is not a payload any reader takes, and only
            # retention would clear it, days later.
            remove_quietly(staged, "staged telemetry file")
            raise

    def _read_telemetries_from_store(self):
        """Reads back the payloads waiting to be retried.

        A file whose contents are not an uploadable payload is discarded; one
        that could not be opened is left alone. See below.
        """
        telemetry_dir = self._telemetry_dir()
        telemetries = []
        if not os.path.exists(telemetry_dir):
            return telemetries
        for filename in sorted(os.listdir(telemetry_dir)):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(telemetry_dir, filename)
            try:
                # Bytes, not text. Decoding here would raise
                # UnicodeDecodeError inside this try, which only handles
                # OSError, aborting the whole flush. Handing bytes to
                # json.loads puts it in the ValueError branch below instead,
                # since UnicodeDecodeError is a ValueError.
                with open(path, "rb") as f:
                    raw = f.read()
            except OSError as e:
                # Skipped, not discarded: failing to open says nothing about
                # the contents. The other process of this app may have it open,
                # which on Windows is enough to refuse the read.
                log.error("could not read stored telemetry {}, leaving it queued: {}".format(path, e))
                continue
            try:
                payload = json.loads(raw)
            except ValueError as e:
                # Discarded: the bytes read are not JSON, and no later flush
                # will make them uploadable.
                self._discard_stored_telemetry(path, "is not valid JSON: {}".format(e))
                continue
            if not is_uploadable_payload(payload):
                self._discard_stored_telemetry(path, "is not an uploadable payload")
                continue
            telemetries.append((payload, path))
        return telemetries

    def _is_backoff_expired(self):
        seconds = self.policy.upload_backoff_seconds()
        if not seconds:
            # Only an explicit "backoff": 0 reaches here; an omitted backoff
            # gets the one day default.
            log.info("The upload backoff is zero, uploads are not throttled")
            return True
        lastupload = self._read_lastupload()
        if not lastupload:
            # Never uploaded, or the stamp was unreadable; _read_lastupload
            # reports both as 0. A backoff spaces uploads, so with no first
            # upload there is nothing to wait for. Treating 0 as an upload at
            # the epoch would let a very large backoff shut the gate on a
            # device that has never sent anything, and only a successful upload
            # rewrites the stamp, so it would stay shut.
            log.info("Nothing has been uploaded from this device yet, the backoff does not apply")
            return True
        # Epoch seconds, not datetimes: the backoff is an unbounded integer
        # from the policy, and datetime arithmetic raises OverflowError well
        # before a uint64 runs out. Subtraction has no such limit, and it also
        # spares fromtimestamp() a corrupt lastupload file.
        elapsed = datetime.now().timestamp() - lastupload
        if elapsed < 0:
            # A stamp ahead of now means the clock moved or the file was
            # edited. Honoring it would shut the gate until that date, and
            # nothing would reopen it: the stamp is rewritten only after an
            # upload. is_expired guards the same case for the policy expiry.
            log.warning("the lastupload time {} is in the future, ignoring the backoff".format(lastupload))
            return True
        # Inclusive: the gate opens *at* the boundary, which is the instant
        # the policy request already named as backOff.
        if elapsed >= seconds:
            log.info("The lastupload time is over the backoff")
            return True
        else:
            log.info("The lastupload time is within the backoff")
            return False

    def _apply_retention_policy(self):
        self._apply_retention_policy_to_telemetry()
        self._apply_retention_policy_to_attachments()

    def _apply_retention_policy_to_telemetry(self):
        # Already in seconds and bytes; the accessor converts the cache from
        # the megabytes the policy states.
        max_age = self.policy.retention_age_seconds()
        max_size = self.policy.retention_cache_bytes()

        telemetry_dir = self._telemetry_dir()
        telemetries = []
        all_size = 0
        try:
            if os.path.exists(telemetry_dir):
                for filename in os.listdir(telemetry_dir):
                    path = os.path.join(telemetry_dir, filename)
                    if filename.endswith(STAGING_SUFFIX) or is_claimed_name(filename):
                        # Neither is a payload any reader picks up, and both
                        # are normally resolved elsewhere, so one still here
                        # past the maximum age never will be.
                        #
                        # Never counted towards the cache size nor reaped to
                        # make room: a live one belongs to work in progress.
                        if time.time() - os.path.getmtime(path) > max_age:
                            remove_reaped_file(path, "abandoned staged or claimed telemetry")
                        continue
                    if filename.endswith(".json"):
                        ts = os.path.getmtime(path)
                        size = os.path.getsize(path)
                        if time.time() - ts <= max_age:
                            all_size += size
                            telemetries.append((ts, size, path))
                        else:
                            remove_reaped_file(path, "session max age")

            telemetries.sort(key=lambda tup: tup[0])
            for ts, size, path in telemetries:
                if all_size > max_size:
                    remove_reaped_file(path, "telemetry max cache")
                    all_size -= size
                else:
                    break

        except IOError as e:
            log.error("I/O error: {}".format(e))
            raise

    def _apply_retention_policy_to_attachments(self):
        # rawFilesAge / rawFilesCache are the v3 names for age / cache,
        # applied to collected files instead of payloads.
        max_age = self.policy.retention_raw_files_age_seconds()
        max_size = self.policy.retention_raw_files_cache_bytes()

        # Every file here is an attachment, named for the GUID of the story
        # that refers to it.
        attach_dir = self.store.directory
        attachments = []
        all_size = 0
        try:
            if os.path.exists(attach_dir):
                for filename in os.listdir(attach_dir):
                    path = os.path.join(attach_dir, filename)
                    if not os.path.isfile(path):
                        continue
                    ts = os.path.getmtime(path)
                    size = os.path.getsize(path)
                    if time.time() - ts <= max_age:
                        all_size += size
                        attachments.append((ts, size, path))
                    else:
                        remove_reaped_file(path, "attachment session max age")

            attachments.sort(key=lambda tup: tup[0])
            for ts, size, path in attachments:
                if all_size > max_size:
                    remove_reaped_file(path, "attachment telemetry max cache")
                    all_size -= size
                else:
                    break

        except IOError as e:
            log.error("I/O error: {}".format(e))
            raise

    def _create_payload(self):
        payload = {}
        report = {}
        # The payload's own version. Unrelated to the policy document schema
        # version; do not bump the two together.
        payload["version"] = 2
        report["env"] = self._create_env()
        payload["pid"] = str(uuid.uuid4())
        payload["tid"] = self.app_id
        payload["did"], payload["did_gen"] = self._get_device_id()
        report["uid"] = self._get_user_id()

        stories = []
        stories.append(self.default_session.stories)
        with self.sessions_lock:
            for session in self.sessions:
                if not session.active:
                    stories.append(session.stories)
        report["stories"] = stories

        reports = []
        reports.append(report)
        payload["reports"] = reports
        return payload

    def _create_env(self):
        env = self.sysinfo.get_systeminfo()
        env["appv"] = self.config["AppVersion"]
        env["sdkv"] = self.sdk_version
        segs = self.config.get("Segments")
        env["d"] = segs if segs else {}
        return env

    def _get_device_id(self):
        if self.options.get("post_did") == "zero":
            return ZERO_UUID, "zero"
        local_path = self._device_id_file()
        if os.path.exists(local_path):
            did = self._get_id(local_path)
        else:
            try:
                shared_path = os.path.join(os.environ["ProgramData"], "Intel Telemetry", "did")
                did = self._get_id(shared_path)
            except:
                did = self._get_id(local_path)
        return did, "random"

    def _get_user_id(self):
        if self.options.get("post_uid") == "zero":
            return ZERO_UUID
        uid = self._get_id(self._user_id_file())
        return uid

    def _get_id(self, path):
        try:
            if os.path.exists(path):
                with open(path, "r") as f:
                    guid = f.read()
                if utils.is_valid_guid(guid):
                    return guid
            guid = str(uuid.uuid4())
            with open(path, "w") as f:
                f.write(guid)
            # Owner-only: this identifier ties every record the machine sends
            # to the same subject. Restricted after the write rather than
            # created restricted, because this path also overwrites a corrupt
            # id in place and create_private refuses an existing name. The
            # owner-only folder above is what protects this on Windows.
            #
            # The return value is deliberately ignored: it has already logged,
            # and the payload carrying the same identifier is written by
            # create_private, which treats its own chmod the same way.
            restrict_to_owner(path)
            return guid
        except IOError as e:
            log.error("I/O error: {}".format(e))
            raise
