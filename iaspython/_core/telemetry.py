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

"""Flavor-independent telemetry: everything the sync and aio clients share.

Private. The public API is iaspython.sync and iaspython.aio.
"""

import os
import time
import uuid
from datetime import datetime
from pathlib import Path
from threading import Lock

import importlib_metadata

from iaspython._core import utils, version
from iaspython._core.exceptions import TelemetryClosed
from iaspython._core.logger import logger as log
from iaspython._core.skr import resolve_ias_telemetry_id
from iaspython._core.store import (
    AttachmentStore,
    attachments_dir,
    check_path_segment,
    makedirs_private,
    resolved_store_folder,
    store_root,
)
from iaspython._core.systeminfo import SystemInfo

ZERO_UUID = "00000000-0000-0000-0000-000000000000"

# What Options["post_did"] and Options["post_uid"] may say.
POSTID_OPTIONS = ("post_did", "post_uid")
POSTID_OPTION_VALUES = ("default", "zero")

# What a stored payload must carry for a record to be built from it. Each is
# read without a default during a build, so a payload missing one would fail
# every build and sit in the store being retried forever.
#
# "tid" is the stored payload's name for the application's id.
REQUIRED_PAYLOAD_KEYS = ("pid", "tid", "did", "version", "reports")

# What a queued payload's name gains while one flush is uploading it, ahead of
# a uniquifying token. Takes the name out of the ".json" readers look for,
# which is what stops a second flush from picking the payload up.
CLAIM_SUFFIX = ".uploading"

# How long a claim can sit untouched before another flush takes it back.
#
# Age is the only available signal: there is no handle on the process that made
# the claim, and it may no longer be running. Long enough that an upload in
# progress is never taken over (which would recreate the double upload claiming
# prevents), short enough that a process killed mid-upload does not strand its
# telemetry until retention ages it out.
CLAIM_GRACE_SECONDS = 3600


def claimed_path_for(path):
    """Returns the name a queued payload takes while this flush uploads it.

    The claim time goes in the name because the file cannot carry it: renaming
    preserves the modification time, which is when the payload was queued. A
    payload queued two hours ago would otherwise look like a two-hour-old claim
    the instant it was claimed.

    The trailing token makes every claim unique, so claiming cannot silently
    overwrite another claim of the same payload, as a POSIX rename would.
    """
    return "{}{}.{}.{}".format(path, CLAIM_SUFFIX, int(time.time()), uuid.uuid4().hex)


def queued_path_for(claimed_path):
    """Returns the name a claimed payload goes back to when the claim is given up."""
    original, _, _ = claimed_path.partition(CLAIM_SUFFIX)
    return original


def claimed_at(claimed_path):
    """Returns when the claim in this name was taken, as a unix timestamp.

    Returns None for a name with no timestamp, which claimed_path_for never
    produces. The caller then leaves the file alone rather than taking back a
    claim that might still be live; retention eventually clears it.
    """
    _, _, tail = claimed_path.partition(CLAIM_SUFFIX + ".")
    stamp, _, _ = tail.partition(".")
    try:
        return int(stamp)
    except ValueError:
        return None


def is_claimed_name(filename):
    """Reports whether some flush has claimed this file, past or present."""
    return CLAIM_SUFFIX + "." in filename


def is_uploadable_payload(payload):
    """Reports whether a stored payload can be turned into a record.

    Checks the nested shape, not just the top-level keys: build_events_content
    walks reports, their stories, and each story list, so "reports": null gets
    past a keys-only check and then fails every build. The uploader reads that
    failure as "not uploaded" and leaves the file to fail again forever.
    """
    if not isinstance(payload, dict):
        return False
    if not all(key in payload for key in REQUIRED_PAYLOAD_KEYS):
        return False
    reports = payload.get("reports")
    if not isinstance(reports, list):
        return False
    for report in reports:
        if not isinstance(report, dict):
            return False
        session_stories = report.get("stories", [])
        if not isinstance(session_stories, list):
            return False
        for stories in session_stories:
            if not isinstance(stories, list):
                return False
            if not all(isinstance(entry, dict) for entry in stories):
                return False
    return True


def remove_reaped_file(path, policy):
    """Deletes a file the retention policy has aged or sized out.

    Failures are logged, not raised. Two processes of the same app reap the
    shared store folder independently, so the file may already be gone or held
    open by the other -- and an upload that succeeded must not surface as an
    exception because housekeeping failed.
    """
    try:
        os.remove(path)
        log.debug("apply {} retention policy, delete {}".format(policy, path))
    except OSError as e:
        log.error("failed to delete {} under the {} retention policy: {}".format(path, policy, e))


class TelemetryBase:
    """In-App Telemetry, shared by the sync and aio clients."""

    def __init__(self, config, *, http_client_class, policy_class, session_class):
        """The constructor of the Telemetry class.

        Args:
            config (dict): Configuration. AppName, AppVersion and TelemetryId
                are required; StoreFolder, CollectorUrl, InternetProxy,
                Segments and Options are optional. TelemetryId is this
                application's own id, which the policy's allow list is
                consulted for.

        Raises:
            TypeError: If config is of the wrong type.
            ValueError: If config is not valid.
        """  # noqa: DOC101,DOC103,DOC502
        # http_client_class, policy_class and session_class are deliberately
        # undocumented above. They are keyword only and are supplied by the
        # sync and aio subclasses, never by an application, and this docstring
        # is published as the public constructor's -- the subclasses inherit it
        # through @wraps. Documenting them would advertise them as parameters
        # to pass. Hence the DOC101/DOC103 suppression; DOC502 is because
        # validate_config() raises rather than this body.
        validate_config(config)
        config["SdkVersion"] = importlib_metadata.version(version.DISTRIBUTION_NAME)
        self.config = config
        # Copied out, not re-read: config is the application's, and a rewrite
        # must not move the store or change who a record says it came from.
        # CollectorUrl is deliberately left live, revalidated by can_upload.
        self.app_name = config["AppName"]
        self.app_id = config["TelemetryId"]
        self.ias_telemetry_id = resolve_ias_telemetry_id()
        self.sdk_version = config["SdkVersion"]
        self.store_folder = resolved_store_folder(config)
        self.options = dict(config.get("Options") or {})
        self.http_client = http_client_class(config.get("InternetProxy"))
        # Built before the policy so the two share one SystemInfo: the policy
        # selector needs the os and cpu facts the payload already collects.
        self.sysinfo = SystemInfo()
        self.policy = policy_class(
            config, self.http_client, sysinfo=self.sysinfo, ias_telemetry_id=self.ias_telemetry_id
        )
        self.session_class = session_class
        # Owned here and lent to every session, so the folder belongs to the
        # store rather than to any one session.
        self.store = AttachmentStore(attachments_dir(config, self.app_name, self.app_id))
        self.default_session = self.session_class(datetime.now(), self.app_id, True, store=self.store)
        self.sessions = []
        self.sessions_lock = Lock()
        self.initialized = True
        log.info("Telemetry initialize done")

    def _check_initialized_or_raise(self):
        if not self.initialized:
            raise TelemetryClosed("Telemetry deinitialized")

    def get_api_version(self):
        """Returns this SDK's version, four-part, e.g. "1.0.0.0".

        The installed distribution's version, which __init__ reads, rather than
        a constant that a build could not stamp. This is the same string sent
        as agentVersion and as the record's source version.

        Returns:
            str: The SDK version.
        """
        return self.sdk_version

    def record_event(self, name, count=1, asum=0, ts=None, segments=None):
        """Records an event against the default session.

        Args:
            name (str): Event name
            count (int, optional): Event count, if not provided, 1 will be used
            asum (float, optional): Event sum, if not provided, 0 will be used
            ts (datetime or int, optional): Timestamp of event, if not provided, current time will be used
            segments (dict, optional): Optional metadata

        Raises:
            TelemetryClosed: If Telemetry was closed.
            TypeError: If an argument is of the wrong type.
            ValueError: If an argument is not valid.
        """  # noqa: DOC502

        self._check_initialized_or_raise()
        self.default_session.record_event(name, count, asum, ts, segments)

    def attach_file(self, name, filepath, ts=None, segments=None, guid=None, compress=False):
        """Attaches a file to the default session.

        Args:
            name (str): Attach event name
            filepath (str): File path to the file
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
        return self.default_session.attach_file(name, filepath, ts, segments, guid, compress)

    def create_session(self, name=None, ts=None, segments=None):
        """Creates a session.

        Args:
            name (str, optional): Session name
            ts (datetime or int, optional): Timestamp of event, if not provided, current time will be used
            segments (dict, optional): Optional metadata

        Returns:
            TelemetrySession: The new session. Its records are uploaded once
            it has been ended and a flush follows.

        Raises:
            TelemetryClosed: If Telemetry was closed.
            TypeError: If an argument is of the wrong type.
            ValueError: If an argument is not valid.
        """  # noqa: DOC502

        self._check_initialized_or_raise()
        ses = self.session_class(ts, self.app_id, False, name, segments, store=self.store)
        with self.sessions_lock:
            self.sessions.append(ses)
        return ses

    def _close_sessions(self):
        with self.sessions_lock:
            for session in self.sessions:
                if session.active:
                    session.end_session()

    def _remove_closed_sessions(self, delete_temps):
        with self.sessions_lock:
            for i in range(len(self.sessions) - 1, -1, -1):
                if not self.sessions[i].active:
                    if delete_temps:
                        self.sessions[i].delete_temp_files()
                    del self.sessions[i]

    def _clear_sessions(self, delete_temps):
        self._remove_closed_sessions(delete_temps)
        if delete_temps:
            self.default_session.delete_temp_files()
        self.default_session = self.session_class(datetime.now(), self.app_id, True, store=self.store)

    def _discard_stored_telemetry(self, path, reason):
        """Deletes a stored payload that can never be uploaded.

        Leaving it would be worse than losing it: every later flush would read
        it, fail on it, and never delete it.
        """
        log.error("discarding stored telemetry {}, it {}".format(path, reason))
        try:
            os.remove(path)
        except OSError as e:
            log.error("failed to delete stored telemetry {}: {}".format(path, e))

    def _claim_stored_telemetry(self, path):
        """Takes this flush's exclusive ownership of a queued payload.

        Two processes of the same application flush from one folder with no
        lock between them. Both can read a payload, but only one can rename it;
        the loser renames a name that is gone and gets an error rather than a
        second copy. Without this, one session's events are uploaded twice
        under different record ids and counted twice.

        Args:
            path (str): The queued payload to claim.

        Returns:
            str|None: The payload's new path, or None if another flush owns it.
        """
        claimed_path = claimed_path_for(path)
        try:
            os.rename(path, claimed_path)
        except OSError as e:
            # Claimed first by another process, or cleaned up. Not an error
            # here: leaving it alone is the correct outcome.
            log.debug("stored telemetry {} is claimed by another flush: {}".format(path, e))
            return None
        return claimed_path

    def _release_stored_telemetry(self, claimed_path):
        """Returns a claimed payload to the queue for a later flush to retry.

        For an upload that did not go through -- offline, or declined -- where
        the payload is still good.
        """
        try:
            os.replace(claimed_path, queued_path_for(claimed_path))
        except OSError as e:
            # Left claimed for _requeue_abandoned_claims to take back. Logged
            # because until then the payload is invisible to every reader.
            log.error("could not requeue stored telemetry {}: {}".format(claimed_path, e))

    def _requeue_abandoned_claims(self):
        """Takes back payloads claimed by a flush that never finished.

        A process killed between claiming and resolving a payload leaves the
        claim behind, and no reader looks at a claimed name. See
        CLAIM_GRACE_SECONDS for the age test and claimed_at for why the age
        comes from the name rather than the file.
        """
        telemetry_dir = self._telemetry_dir()
        if not os.path.exists(telemetry_dir):
            return
        for filename in os.listdir(telemetry_dir):
            if not is_claimed_name(filename):
                continue
            path = os.path.join(telemetry_dir, filename)
            taken_at = claimed_at(path)
            if taken_at is None:
                log.error("cannot tell how old the claim on {} is, leaving it".format(path))
                continue
            if time.time() - taken_at < CLAIM_GRACE_SECONDS:
                continue
            try:
                # os.replace, not os.rename: Windows refuses a rename onto an
                # existing name.
                os.replace(path, queued_path_for(path))
                log.info("took back an abandoned claim on stored telemetry {}".format(path))
            except OSError as e:
                log.error("could not take back the abandoned claim {}: {}".format(path, e))

    def _telemetry_dir(self):
        return os.path.join(self.store_folder, self.app_name, self.app_id, "telemetry")

    def _attachments_dir(self):
        """Returns the attachments folder, as reported by the store that owns it."""
        return self.store.directory

    def _app_dir(self):
        return os.path.join(self.store_folder, self.app_name, self.app_id)

    def _device_id_file(self):
        """This store's copy of the device id.

        Directly in the store folder, above the app name, so every app the
        user runs reports the same device. The shared %ProgramData% copy that
        _get_device_id prefers is wider still, across agents.
        """
        return os.path.join(self.store_folder, "did")

    def _user_id_file(self):
        return os.path.join(self.store_folder, "uid")


def validate_url(url, *, require_tls):
    """Raises ValueError for an unusable URL, or optionally a non-https one.

    Args:
        url (str): The URL to check.
        require_tls (bool): Keyword-only and without a default, because the two
            callers differ. A CollectorUrl is a telemetry destination and must
            be https. An InternetProxy is not a destination -- it is asked to
            CONNECT and TLS runs end to end inside the tunnel -- so an
            http:// proxy URL is normal and safe.

    Raises:
        ValueError: If the URL is unusable, or require_tls and it is not https.
    """
    parsed = utils.parse_url(url)
    if parsed is None or not parsed.scheme or not parsed.hostname:
        raise ValueError('URL="{}" is not valid'.format(utils.strip_url_secrets(url)))
    if require_tls and not utils.is_tls_url(url):
        raise ValueError(
            'URL="{}" is not https. Telemetry carries the device and user identifiers and '
            "every collected event, so it is only ever uploaded over TLS. There is no way to "
            "configure a cleartext destination.".format(utils.url_origin(url))
        )


def create_store_folder(config):
    """Creates and returns the folder the SDK will write its store in.

    StoreFolder names a root to put the store under, not the store itself:
    STORE_FOLDER_NAME is appended either way, so the layout below is the same
    whether or not an application configures one.
    """
    root = store_root(config)
    store_folder_path = Path(resolved_store_folder(config))

    # The root is checked too: a file named as the root would otherwise only
    # fail later, as whatever error mkdir raises for a non-directory parent.
    for candidate in (root, store_folder_path):
        if candidate.exists() and not candidate.is_dir():
            raise NotADirectoryError("configured store folder is a file")

    # makedirs_private, not Path.mkdir: this creates the first part of the
    # store, and everything below inherits from it. mkdir's default left
    # "Intel Telemetry" world-readable, and the device and user identifiers are
    # written directly into it. On Windows the folder ACL is the whole of the
    # protection, since a file there does not carry its own mode.
    #
    # An existing root is left as it is, so only levels the SDK creates itself
    # become owner-only.
    makedirs_private(str(store_folder_path))
    return str(store_folder_path)


def validate_config(config):
    """Raises TypeError or ValueError on the first thing wrong with the config."""
    # mandatory parameters
    app_name = config["AppName"]
    app_version = config["AppVersion"]
    tid = config["TelemetryId"]

    if not isinstance(app_name, str):
        raise TypeError("AppName must be string, got {}".format(type(app_name)))
    if not isinstance(app_version, str) and not isinstance(app_version, int) and not isinstance(app_version, float):
        raise TypeError("AppVersion must be string, int or float, got {}".format(type(app_version)))
    if not isinstance(tid, str):
        raise TypeError("TelemetryId must be string, got {}".format(type(tid)))

    if not utils.is_valid_guid(tid):
        raise ValueError("Invalid TelemetryId {}".format(tid))
    # The store layout is <store>/<AppName>/<TelemetryId>/..., so both are
    # application input that becomes a path. The id is covered above.
    check_path_segment(app_name, "AppName")

    # optional parameters
    # CollectorUrl overrides the authority from the policy document.
    if "CollectorUrl" in config:
        collector_url = config["CollectorUrl"]
        if not isinstance(collector_url, str):
            raise TypeError("CollectorUrl must be string, got {}".format(type(collector_url)))
        # An empty string means "unset", same as omitting the key:
        # PolicyBase.get_telemetry_url falls back to the policy authority.
        if collector_url:
            validate_url(collector_url, require_tls=True)
    if "Options" in config:
        options = config["Options"]
        if not isinstance(options, dict):
            raise TypeError("Options must be dict, got {}".format(type(options)))
        # Checked, not ignored: the readers test for "zero", so an unrecognized
        # value would quietly mean "post the real identifier". Other Options
        # keys are the caller's; only these two suppress an identifier.
        for key in POSTID_OPTIONS:
            if key in options and options[key] not in POSTID_OPTION_VALUES:
                raise ValueError(
                    "Options[{}] must be one of {}, got {!r}".format(key, POSTID_OPTION_VALUES, options[key])
                )
    if "StoreFolder" in config:
        store_folder = config["StoreFolder"]
        if not isinstance(store_folder, str):
            raise TypeError("StoreFolder must be string, got {}".format(type(store_folder)))
    if "Segments" in config:
        segments = config["Segments"]
        if not isinstance(segments, dict):
            raise TypeError("Segments must be dict, got {}".format(type(segments)))
    if "InternetProxy" in config:
        proxy = config["InternetProxy"]
        if not isinstance(proxy, str):
            raise TypeError("InternetProxy must be string, got {}".format(type(proxy)))
        # See validate_url for why a proxy may be http.
        validate_url(proxy, require_tls=False)

    create_store_folder(config)
