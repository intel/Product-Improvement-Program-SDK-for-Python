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

"""Whether this interpreter can give the store owner-only permissions on Windows.

A Windows file takes the ACL of the folder it is created in, and os.chmod
there only moves the read-only flag, so the folder ACL is the whole of the
protection. Only the interpreter can set it: os.mkdir(path, 0o700) makes
CPython build a descriptor granting SYSTEM, Administrators and the owner
alone, which arrived in 3.11.10 and 3.12.4 as the fix for CVE-2024-4030
(gh-118486). Earlier releases ignore the mode and inherit from the parent,
silently -- nothing is wrong on POSIX, so no test notices.

The SDK deliberately does not apply the descriptor itself through advapi32: a
subtly wrong security descriptor grants access rather than erroring, and no
POSIX test would catch it. The condition is reported instead.
"""

import os
import sys

from iaspython._core.logger import logger as log

# The first release on each supported line where os.mkdir(path, 0o700)
# restricts the directory.
FIRST_RESTRICTING = {(3, 11): (3, 11, 10), (3, 12): (3, 12, 4)}

# Said once per process: makedirs_private creates several levels at a time and
# runs again on any flush that finds them gone.
_reported = False


def interpreter_restricts_new_directories():
    """Reports whether os.mkdir(path, 0o700) yields an owner-only directory.

    Always true off Windows, where the mode carries the permissions. On
    Windows it is a version check, since reading the ACL back would need the
    Win32 calls this module exists to avoid. Version checks normally miss
    distribution backports, but Windows Pythons carry none.
    """
    if os.name != "nt":
        return True
    current = sys.version_info[:3]
    threshold = FIRST_RESTRICTING.get(sys.version_info[:2])
    if threshold is None:
        # 3.13 and up have it; anything below 3.11 is not a supported
        # interpreter, and answering False for it is the safe way to be wrong.
        return sys.version_info[:2] >= (3, 13)
    return current >= threshold


def report_if_store_cannot_be_restricted(path):
    """Reports, once, that a store folder is being created without protection.

    Logged rather than raised: telemetry must not take the application down,
    so the caller carries on with a less private store.

    Args:
        path (str): The store folder being created.

    Returns:
        bool: Whether the folder will be owner-only.
    """
    if interpreter_restricts_new_directories():
        return True

    global _reported
    if not _reported:
        _reported = True
        log.error(
            "Python {} on Windows cannot restrict a new directory to its owner, so the telemetry store at "
            '"{}" keeps whatever permissions the folder above it grants instead of being restricted to you '
            "-- including for the device and user identifiers in it. os.mkdir's 0o700 mode is ignored before "
            "3.11.10 and 3.12.4 (CVE-2024-4030); run on 3.11.10, 3.12.4 or later, or point StoreFolder at a "
            "location that is already restricted.".format(".".join(str(n) for n in sys.version_info[:3]), path)
        )
    return False
