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

"""Predicate primitives for matching a v3 policy selector against a device.

A device must land in the same sample population however its telemetry is
collected, so these rules are fixed by RFD-0031 rather than chosen. Where this
file deviates deliberately, the comment says so.

Pure functions over plain values, so they can be tested without a config dict,
a store folder or a SystemInfo.

policy documentation:
  RFD-0031, frameworks.telemetry.skylight-ridge.rfd
"""

import hashlib
import hmac
import re
import uuid

from iaspython._core.logger import logger as log

# 0x28f5c28f5c28f5c == UINT64_MAX // 100, i.e. one percent of the 64-bit range.
# The sampling threshold is this times the percentage.
ONE_PERCENT_OF_UINT64MAX = 0x28F5C28F5C28F5C

# HMAC-SHA256 takes at most a 64 byte key; the seed occupies the first 8 and
# the rest stays zero.
HMAC_KEY_LENGTH = 64

UINT64_MASK = 0xFFFFFFFFFFFFFFFF

# a leading integer, with an optional sign and leading space
_LEADING_INT = re.compile(r"\s*([+-]?[0-9]+)")

_DIGITS = "0123456789"

# A version component is compared as a signed 32-bit integer. Python integers
# are unbounded, so this bound is load-bearing: without it "<999999999999.0.0"
# would match here and be rejected by every other agent.
INT_MIN = -(2**31)
INT_MAX = 2**31 - 1


def leading_int(text):
    """Reads a leading integer, stopping at the first unusable character.

    Deliberately not int(): "10abc" is 10 here, while int("10abc") raises. The
    policy version tables depend on it -- a component of "*" must fail, but
    one with trailing garbage must not.

    Args:
        text (str): The value to read a leading integer from.

    Returns:
        int: The leading integer.

    Raises:
        ValueError: When no digits lead, or the value will not fit the 32-bit
            range a component is compared in. version_match treats both the
            same: an unreadable pattern does not match.
    """
    match = _LEADING_INT.match(text)
    if not match:
        raise ValueError("no leading integer in {!r}".format(text))
    value = int(match.group(1))
    if value < INT_MIN or value > INT_MAX:
        raise ValueError("{!r} is out of range for a version component".format(text))
    return value


def version_match(pattern, version):
    """Reports whether a version satisfies a pattern.

    The pattern is an optional comparison prefix (<, <=, =, >=, >) followed by
    a dotted version; a bare version means equality. Components are compared
    as integers, left to right, short-circuiting on the first decisive one.

    Different component counts never match, so ">=10.0.19044.0" only matches a
    four-part version. An empty or malformed pattern is False rather than
    fatal; see has_version_match.
    """
    if not pattern or not version:
        return False

    # Two-character prefixes before one-character ones, or "<=" reads as "<"
    # and leaves "=1.2.3" to parse.
    if pattern.startswith("<="):
        op, pattern_version = "<=", pattern[2:]
    elif pattern.startswith(">="):
        op, pattern_version = ">=", pattern[2:]
    elif pattern.startswith("<"):
        op, pattern_version = "<", pattern[1:]
    elif pattern.startswith("="):
        op, pattern_version = "=", pattern[1:]
    elif pattern.startswith(">"):
        op, pattern_version = ">", pattern[1:]
    elif pattern[0] in _DIGITS:
        op, pattern_version = "=", pattern
    else:
        log.error("invalid version pattern {}".format(pattern))
        return False

    try:
        pattern_parts = [leading_int(part) for part in pattern_version.split(".")]
        version_parts = [leading_int(part) for part in version.split(".")]
    except ValueError as e:
        log.info("could not read version pattern {} or version {}: {}".format(pattern, version, e))
        return False

    if len(pattern_parts) != len(version_parts):
        return False

    result = 0
    for pattern_part, version_part in zip(pattern_parts, version_parts):
        # -1, 0 or 1 for version below, equal to, or above the pattern.
        result = (version_part > pattern_part) - (version_part < pattern_part)

        # A decisive component ends it; an equal one moves to the next.
        if op in ("<", "<="):
            if result > 0:
                return False
            if result < 0:
                return True
        elif op == "=":
            if result != 0:
                return False
        elif op in (">", ">="):
            if result < 0:
                return False
            if result > 0:
                return True

    # Every component compared equal, so the verdict rests on whether the
    # operator admits equality.
    if op == "<" and result >= 0:
        return False
    if op == "<=" and result > 0:
        return False
    if op == "=" and result != 0:
        return False
    if op == ">" and result <= 0:
        return False
    if op == ">=" and result < 0:
        return False
    return True


def has_version_match(patterns, version):
    """Reports whether any pattern matches. An empty list is False.

    Note the asymmetry with is_empty_or_contains, where empty means "match
    everything": callers guard on the list being non-empty, so an empty one
    reaching here is a malformed selector rather than a wildcard.
    """
    if not patterns:
        return False
    return any(version_match(pattern, version) for pattern in patterns)


def sample_hmac_value(guid, seed):
    """Returns the 64-bit value a guid and seed hash to.

    Public so a test can pin the byte layout. Three details must match
    exactly, and a mistake in any of them is invisible -- it just samples a
    different population:

      * the message is the raw 16 byte Windows GUID struct, which is
        uuid.UUID.bytes_le (Data1/Data2/Data3 little-endian), NOT .bytes
      * the key is the seed as a little-endian uint64 followed by zeroes
      * the digest's first 8 bytes are read big-endian
    """
    key = bytearray(HMAC_KEY_LENGTH)
    key[0:8] = (int(seed) & UINT64_MASK).to_bytes(8, "little")
    message = uuid.UUID(str(guid)).bytes_le
    digest = hmac.new(bytes(key), message, hashlib.sha256).digest()
    return int.from_bytes(digest[0:8], "big")


def is_sampled_guid(guid, percent, seed):
    """Reports whether a guid falls inside the given percentage of the population.

    Stable for a given guid and seed, so a device stays in or out across runs
    rather than being re-rolled every flush. Changing the seed reshuffles
    which slice is selected without changing its size.
    """
    if percent <= 0:
        return False
    if percent >= 100:
        # Checked before the guid, so 100% samples a device whose id is not
        # known yet. An absent id is only ever sampled when sampling is off.
        return True
    if not guid:
        log.info("no guid to sample")
        return False

    try:
        value = sample_hmac_value(guid, seed)
    except (AttributeError, TypeError, ValueError) as e:
        log.error("could not sample guid: {}: {}".format(type(e), e))
        return False

    return value < ONE_PERCENT_OF_UINT64MAX * percent


def _folded(value):
    """Casefolds a string, returning None for anything that is not one.

    None never compares equal to a folded string, so a selector carrying a
    number where a string belongs fails to match rather than raising.
    """
    return value.casefold() if isinstance(value, str) else None


def is_empty_or_contains(values, value):
    """Reports whether values is empty, or contains value.

    An empty list means "no constraint" and matches everything. Comparison is
    case-insensitive per RFD-0031. Both sides are folded, deliberately a
    superset of folding only the device side, which would fail to match a
    policy that spelled a value with capitals.
    """
    if not values:
        return True
    folded = _folded(value)
    if folded is None:
        return False
    return any(_folded(candidate) == folded for candidate in values)


def contains_prefix(values, value, chars):
    """Reports whether values is empty, or contains value truncated to chars.

    Only entries exactly chars long are considered, which makes this a
    "signature without its stepping" test rather than a general prefix test:
    "0x806e" matches the device's "0x806ec", but "0x806e7" does not.
    """
    if not values:
        return True
    if not isinstance(value, str) or len(value) < chars:
        return False
    prefix = _folded(value[:chars])
    return any(
        isinstance(candidate, str) and len(candidate) == chars and _folded(candidate) == prefix for candidate in values
    )
