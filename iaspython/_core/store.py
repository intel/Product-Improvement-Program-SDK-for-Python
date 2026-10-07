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
import shutil
import stat
import time
from pathlib import Path

from iaspython._core.logger import logger as log
from iaspython._core.winacl import report_if_store_cannot_be_restricted

# The folder the store lives in, under whatever root StoreFolder names. Every
# agent appends this same name, so an app instrumented with more than one of
# them keeps a single telemetry folder.
STORE_FOLDER_NAME = "Intel Telemetry"

# The folder attachment content goes in, below the telemetry id. A folder of
# its own, so every file in it is an attachment named by its GUID and the
# retention sweep needs no filtering.
ATTACHMENTS_FOLDER_NAME = "attachments"

# Appended to a file still being written, before it is renamed onto its real
# name. Deliberately not ending in ".json", so the other process of this app
# passes over a write in progress rather than reading a partial file, judging
# it invalid JSON, and deleting it.
STAGING_SUFFIX = ".tmp"


def user_store_root():
    """Returns the default store folder when the caller names none.

    %LOCALAPPDATA% on Windows, ~/.cache elsewhere, so the store lands where a
    POSIX system expects regenerable data rather than beside the user's files.
    """
    if "LOCALAPPDATA" in os.environ:
        return Path(os.environ["LOCALAPPDATA"])
    if "HOME" in os.environ:
        return Path(os.environ["HOME"]) / ".cache"
    return Path.cwd()


def store_root(config):
    """Returns the folder StoreFolder names, or the user default."""
    raw = config.get("StoreFolder")
    return Path(raw) if raw else user_store_root()


def resolved_store_folder(config):
    """Returns the store folder: the root with STORE_FOLDER_NAME below it.

    Derived on every call rather than written back into config, so building a
    Telemetry twice from one dict does not append the name twice.
    """
    return str(store_root(config) / STORE_FOLDER_NAME)


def attachments_dir(config, app_name, app_id):
    """Returns <store>/<app>/<app_id>/attachments."""
    return os.path.join(resolved_store_folder(config), app_name, app_id, ATTACHMENTS_FOLDER_NAME)


# The separators and the drive colon escape the store; the rest Windows
# refuses outright, so a bad name fails validation rather than mkdir.
# Deliberately not an alphanumeric allowlist: an application name is a display
# string, and one with a space or an accent has to keep working.
SEGMENT_ILLEGAL_CHARS = '<>:"/\\|?*'

# Microsoft's list, reserved whatever extension follows -- "CON.log" is still
# the console, and a folder named NUL is swallowed rather than created.
# Windows 11 does create the rest; they are refused here to stay portable.
_DEVICE_DIGITS = "0123456789¹²³"
SEGMENT_RESERVED_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + ["COM{}".format(d) for d in _DEVICE_DIGITS]
    + ["LPT{}".format(d) for d in _DEVICE_DIGITS]
)

# Bytes, because that is how a filesystem caps one name (255 on ext4). Also
# keeps the store path inside the 260 Windows enforces without long paths.
SEGMENT_MAX_BYTES = 64


def check_path_segment(value, name):
    """Raises ValueError unless value can be one folder inside the store.

    The layout is <store>/<AppName>/<TelemetryId>/..., so each segment is
    application input that becomes a path. TelemetryId is already held to a
    GUID; this is the same guarantee for the rest.

    Rejected rather than sanitized: a name quietly rewritten would put an
    application's telemetry in a folder it cannot name again.
    """
    if not value:
        raise ValueError("{} must not be empty".format(name))
    # Before the length check, which encodes: an unpaired surrogate is a
    # filename on Windows but raises inside fsencode on Linux.
    for char in value:
        code = ord(char)
        if char in SEGMENT_ILLEGAL_CHARS or code < 32 or code == 127 or 0xD800 <= code <= 0xDFFF:
            raise ValueError("{}={!r} must not contain {!r}".format(name, value, char))
    # fsencode, so the count is in the encoding the filesystem will be given.
    encoded_len = len(os.fsencode(value))
    if encoded_len > SEGMENT_MAX_BYTES:
        raise ValueError("{} must be at most {} bytes, got {}".format(name, SEGMENT_MAX_BYTES, encoded_len))
    # Covers "." and ".." too. Windows also drops a trailing dot or space, so
    # "app." and "app" would name one folder under two configured names.
    if value != value.rstrip(". "):
        raise ValueError("{}={!r} must not end in a dot or a space".format(name, value))
    if value.partition(".")[0].upper() in SEGMENT_RESERVED_NAMES:
        raise ValueError("{}={!r} is a reserved device name".format(name, value))


# Owner read/write, nothing for group or others. Set explicitly because
# os.open() asks for 0o666 and the umask commonly leaves 0o644, which every
# other user on the machine can read -- and everything the SDK writes describes
# the instrumented application: attachments, and payloads carrying the device
# id and event stories.
#
# Windows ignores these bits for files; a file there inherits the ACL of the
# folder it is created in. See STORE_DIR_MODE, which is where the protection
# comes from on that platform.
STORE_FILE_MODE = 0o600

# Owner may read, write and enter; nobody else may. Set explicitly because
# os.makedirs asks for 0o777 and the umask commonly leaves 0o755, letting every
# user list the store. The files are owner-only, so that exposes names rather
# than contents -- but the path is <store>/<app name>/<telemetry id>, and a
# staged payload announces a flush in progress.
#
# On Windows this protects the whole store: CPython hands CreateDirectoryW an
# explicit security descriptor (SYSTEM, Administrators, OWNER RIGHTS, parent
# inheritance off) and the files below inherit it.
#
# It must be exactly 0o700, which CPython special-cases. 0o750, 0o770, 0o600
# and even the stricter 0o500 fall back to inheriting the parent's ACL, so
# "tightening" this would switch the Windows protection off silently. A test
# pins it. Only from 3.11.10 and 3.12.4; earlier interpreters ignore the mode,
# which winacl reports rather than works around.
STORE_DIR_MODE = 0o700

# Retry budget for creating something inside a folder another process of this
# app made moments ago. Between that process's mkdir and its chmod, a umask
# clearing an owner bit leaves the folder briefly unwritable even by its owner,
# and the loser of the race sees PermissionError on a good location. The window
# is two statements wide, so waiting it out is the whole fix.
CREATE_ATTEMPTS = 3
CREATE_RETRY_SECONDS = 0.01


def mkdir_private(directory):
    """Creates one folder, owner-only.

    The chmod is not redundant: the umask subtracts from what mkdir asks for,
    and can leave a folder the SDK cannot write into. chmod is not filtered
    that way, and cannot widen anything.

    Args:
        directory (str): The folder to create.

    Returns:
        bool: False if another process created it first.

    Raises:
        PermissionError: If the folder could not be created after
            CREATE_ATTEMPTS tries.
    """
    for attempt in range(CREATE_ATTEMPTS):
        try:
            os.mkdir(directory, STORE_DIR_MODE)
            # set_mode logs rather than raises, so it cannot be mistaken for
            # the race CREATE_ATTEMPTS is about.
            set_mode(directory, STORE_DIR_MODE)
            return True
        except FileExistsError:
            # The other process got there first, which is the outcome we
            # wanted. The mode on what it created is its own to set.
            return False
        except PermissionError:
            if attempt == CREATE_ATTEMPTS - 1:
                raise
            time.sleep(CREATE_RETRY_SECONDS)


def makedirs_private(path):
    """Creates a folder and any missing parents, owner-only.

    One level at a time, because os.makedirs applies its mode to the last
    folder alone -- every parent it creates lands on 0o777 minus the umask,
    and a folder can be listed by anyone who can enter its parent.

    An existing folder is left as it is, permissions included: it may be one an
    administrator laid out.

    Races with the other process of this app are lost gracefully. The loser
    sees FileExistsError, or a PermissionError that mkdir_private waits out.
    """
    missing = []
    current = os.path.abspath(path)
    while not os.path.isdir(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            # Reached the root, which always exists.
            break
        current = parent

    if missing:
        # Only when something is about to be created, and named by the folder
        # asked for rather than the outermost one created to reach it.
        report_if_store_cannot_be_restricted(path)

    for directory in reversed(missing):
        mkdir_private(directory)


def restrict_to_owner(path):
    """Puts owner-only permissions on a file the SDK has just written.

    For files created by a plain open() because they are overwritten in place
    -- the device and user identifiers, regenerated over a corrupt one --
    where create_private cannot be used because it refuses an existing name.
    The file is briefly at whatever open() produced, but only inside a folder
    already made owner-only.

    Args:
        path (str): The file to restrict.

    Returns:
        bool: Whether the file is now owner-only. Reported rather than assumed,
        because this tightens a mode the machine chose rather than restoring
        one the umask trimmed: a chmod that did not happen leaves the
        identifier at the default.
    """
    return set_mode(path, STORE_FILE_MODE)


def mode_kept(path, mode, st_mode):
    """Reports whether a chmod that returned without error actually took.

    A store on FAT, exFAT or a CIFS mount accepts the call and keeps the single
    mode it synthesizes for the whole filesystem, leaving the file as readable
    as it was. Unlike an error, that leaves no trace, so the mode is read back.

    Always True on Windows, where st_mode is synthesized from the read-only
    flag and the folder ACL is what protects the file.
    """
    if os.name == "nt":
        return True

    actual = stat.S_IMODE(st_mode)
    if actual == mode:
        return True

    log.error(
        'Mode {:o} was set on "{}" without error, but it is still {:o}. This filesystem does not keep '
        "permissions, so the file is only as private as the folder holding it.".format(mode, path, actual)
    )
    return False


def set_mode(path, mode):
    """Puts an exact mode on something the SDK just created.

    Failures are logged and reported rather than raised: the caller has a
    usable file either way, and a failed flush is the worse outcome. It costs
    little for mkdir_private and create_private, which only restore what the
    umask trimmed, but restrict_to_owner would be left at the machine default.

    Args:
        path (str): The file or folder to change.
        mode (int): The exact mode to apply.

    Returns:
        bool: Whether the mode took.
    """
    try:
        os.chmod(path, mode)
        return mode_kept(path, mode, os.stat(path).st_mode)
    except OSError as e:
        log.error('Could not set mode {:o} on "{}": {}'.format(mode, path, e))
        return False


def create_private(path):
    """Creates an empty file only its owner can read, failing if it exists.

    For files then written through open() or AIOFile, which take a filename
    rather than a descriptor and so cannot be told what permissions to create
    with. open(path, "w") applies permissions only when it creates the file,
    so creating it here and letting the writer truncate it leaves it at
    STORE_FILE_MODE with no readable moment in between.

    O_EXCL because an existing name is not ours to write over: a plain open()
    would follow a symlink planted there, or truncate someone else's file.

    Args:
        path (str): The file to create.

    Returns:
        str: The path, so a caller records the file as its own to clean up
        only once it exists.

    Raises:
        PermissionError: If the file could not be created privately.
    """
    for attempt in range(CREATE_ATTEMPTS):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, STORE_FILE_MODE)
            break
        except PermissionError:
            # The folder above may be one another process is still
            # permissioning. See CREATE_ATTEMPTS.
            if attempt == CREATE_ATTEMPTS - 1:
                raise
            time.sleep(CREATE_RETRY_SECONDS)

    try:
        # The umask subtracts from what os.open asked for, and a host clearing
        # an owner bit would leave a file the writer below cannot reopen. Done
        # through the descriptor so it cannot be aimed elsewhere in between.
        # fchmod is POSIX-only; the bits mean nothing on Windows.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, STORE_FILE_MODE)
            # Read back through the same descriptor. See mode_kept.
            mode_kept(path, STORE_FILE_MODE, os.fstat(fd).st_mode)
    except OSError as e:
        log.error('Could not set mode {:o} on "{}": {}'.format(STORE_FILE_MODE, path, e))
    finally:
        os.close(fd)
    return path


def remove_quietly(path, what):
    """Deletes a file nothing refers to any more, logging rather than raising.

    Used on cleanup paths, where the caller must see the failure that got it
    here rather than a cleanup problem stacked on top.
    """
    try:
        if path and os.path.exists(path):
            os.remove(path)
            log.debug('deleted {} "{}"'.format(what, path))
    except OSError as e:
        log.error('Could not delete {} "{}": {}'.format(what, path, e))


def default_attachment_dir(app_id):
    """Returns where attachments go when nobody said where.

    Inside the store, never the system temp folder, so attachments fall under
    the same retention policy as everything else the SDK writes.

    Only reached by a session built directly, which has no AppName to sit
    under, so it sits below the store folder under its application id.
    """
    return os.path.join(resolved_store_folder({}), app_id, ATTACHMENTS_FOLDER_NAME)


class AttachmentStore:
    """The folder attachment content lives in, and the rules for putting it there.

    One attachment is one file named after its GUID. That is the whole index:
    a payload refers to its attachments by GUID alone.

    Telemetry owns one and lends it to every session, so sessions ask it to
    place files without knowing where it is.
    """

    def __init__(self, directory):
        """Binds the store to the folder its attachments live in.

        Args:
            directory (str): The folder attachments are stored in. Required,
                since a default needs a telemetry id (see
                default_attachment_dir) and both callers already have one.
        """
        self.directory = directory

    def path_for(self, guid):
        """Returns the path an attachment with this GUID is stored at."""
        return os.path.join(self.directory, guid)

    def staging_path(self, guid):
        """Returns where a compressed attachment is built before place() moves it.

        Inside the store, because a file is created with the permissions of the
        folder it is born in, and a rename carries its own ACL across rather
        than re-inheriting at the destination. Built in the system temp folder
        it would keep that folder's permissions all the way here. It also means
        the rename in place() never crosses a filesystem, and that a staged
        file left by a crash is somewhere retention already looks.

        The folder *above* the attachments, since every file in the attachments
        folder is expected to be an attachment named by its GUID.
        """
        return os.path.join(self.staging_dir(), "{}.gz{}".format(guid, STAGING_SUFFIX))

    def staging_dir(self):
        """Returns the folder staged files are built in: above the attachments.

        Always exists by the time anything stages into it, being the parent of
        the attachments folder. See staging_path.
        """
        return os.path.dirname(self.directory)

    def zip_staging_path(self, record_uuid):
        """Returns where a record's attachment ZIP is built before upload.

        Same folder and reasoning as staging_path. Named by the record UUID so
        racing flushes cannot collide, and carrying STAGING_SUFFIX so an
        abandoned one is reaped with the rest.
        """
        return os.path.join(self.staging_dir(), "{}.zip{}".format(record_uuid, STAGING_SUFFIX))

    def holds(self, filepath, guid):
        """Reports whether filepath already is the stored file for this GUID.

        attach() writes its payload straight to the stored path and hands that
        path to attach_file, so it arrives already claimed and in place.
        """
        dest = self.path_for(guid)
        return os.path.exists(dest) and os.path.samefile(filepath, dest)

    def claim(self, guid):
        """Claims the path for a GUID, raising ValueError if it is in use.

        A payload refers to its attachment content by GUID alone, so
        overwriting a stored file would swap the content out from under a
        payload awaiting retry -- and the retry would then delete it, leaving
        the newer record pointing at nothing. A reused GUID is caller error.

        Staked by creating the file exclusively rather than by testing for
        absence: nothing serializes two processes of the same app, so both
        would pass an existence check and write the same destination.

        Args:
            guid (str): GUID of the attachment to claim a path for.

        Returns:
            str: The claimed path, which the content is then written to.

        Raises:
            ValueError: If the GUID already has a stored file.
            OSError: If the path could not be claimed.
        """
        dest = self.path_for(guid)
        try:
            makedirs_private(self.directory)
            create_private(dest)
        except FileExistsError:
            log.error("attachment guid already in use: {}".format(guid))
            raise ValueError('attachment guid "{}" already has a stored file at "{}"'.format(guid, dest))
        except OSError as e:
            log.error('Could not claim attachment path "{}": {}'.format(dest, e))
            raise
        log.debug("claimed attachment path {}".format(dest))
        return dest

    def release(self, claimed_path):
        """Drops a claim whose attachment never made it into a session."""
        remove_quietly(claimed_path, "claimed attachment path")

    def place(self, filepath, guid, move):
        """Puts an attachment's content in the store under its GUID.

        The destination is the claim staked by claim(), so it already exists as
        an empty file and is overwritten in place here.

        Args:
            filepath (str): The file to store
            guid (str): GUID of the attachment, used as the stored filename
            move (bool): Move the file instead of copying it. Only safe for
                         files the SDK created itself; a caller's file is copied
                         so that attaching it does not consume it.

        Returns:
            str: The path the attachment was stored at.

        Raises:
            OSError: If the content could not be written to the store.
        """
        dest = self.path_for(guid)
        if self.holds(filepath, guid):
            # Already stored; attach() writes its payload straight into place.
            return dest
        try:
            if move:
                try:
                    # os.replace, not shutil.move: the claim already sits at
                    # dest, and a rename onto an existing file fails on Windows.
                    os.replace(filepath, dest)
                    # The claim has been replaced wholesale by the staged file,
                    # which carries its own permissions across the rename.
                    # Those are already correct, since staging_path builds
                    # inside this store; this restates them.
                    self._restrict_to_owner(dest)
                except OSError:
                    # A rename cannot cross filesystems. Staging inside the
                    # store means it normally does not have to, so this is the
                    # fallback for a store split across mounts. The copy writes
                    # into the claimed file, which keeps its own permissions.
                    shutil.copyfile(filepath, dest)
                    remove_quietly(filepath, "compressed attachment file")
            else:
                # Likewise a copy into the claimed file.
                shutil.copyfile(filepath, dest)
        except OSError as e:
            log.error('Could not store attachment "{}" as "{}": {}'.format(filepath, dest, e))
            raise
        log.debug("stored attachment {}".format(dest))
        return dest

    def _restrict_to_owner(self, path):
        """Sets a stored attachment back to owner-only permissions.

        Needed after os.replace, which swaps in a different file entirely
        rather than adjusting the existing one. See STORE_FILE_MODE. Does
        nothing meaningful on Windows.
        """
        restrict_to_owner(path)
