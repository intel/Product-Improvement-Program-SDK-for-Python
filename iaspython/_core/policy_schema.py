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

"""The v3 policy document: parsing, selector evaluation, and fragment merging.

Three-way optionality is the thing to keep in mind throughout. A field can be
absent, present as JSON null, or present with a value, and the three mean
different things when merging: absent keeps what is already there, null
*erases* it, and a value replaces or merges into it. That is why this module
carries an ABSENT sentinel instead of normalizing into a plain dict -- a dict
would have to spell both "absent" and "erased" as None.

policy documentation:
  RFD-0031, frameworks.telemetry.skylight-ridge.rfd
"""

import copy

from iaspython._core.logger import logger as log
from iaspython._core.policy_match import (
    contains_prefix,
    has_version_match,
    is_empty_or_contains,
    is_sampled_guid,
)

POLICY_VERSION = 3

# The schema's documented default for a missing Endpoint.backoff. Note that
# it therefore throttles to once a day, where a missing v2
# session_min_upload_backoff meant no throttling at all.
DEFAULT_UPLOAD_BACKOFF_SECONDS = 86400

# The protocol this SDK speaks. An endpoint advertising anything else is not
# one we know how to upload to.
SKR_V2_PROTOCOL = "skr_v2"

# The length of a cpu signature with its stepping trimmed off: "0x806e" is the
# six characters that remain of a device's "0x806ec".
CPU_SIGNATURE_NO_STEPPING = 6

# The largest value the schema's numbers can hold. Python ints do not
# overflow, so without this the SDK would act on sampling, expiry or backoff
# values that a 64-bit parse -- and so every other agent -- rejects.
UINT64_MAX = 2**64 - 1

HEADER_KEY = "header"
HEADER_VERSION_KEY = "version"
HEADER_ID_KEY = "id"
HEADER_TS_KEY = "ts"
EXPIRATION_KEY = "expiration"
GLOBAL_SELECTOR_KEY = "globalSelector"
FRAGMENTS_KEY = "fragments"

ENDPOINT_KEY = "_endpoint"
RETENTION_KEY = "_retention"
SELECTOR_KEY = "_selector"

IAS_MANIFEST_KEY = "ias"
IAS_MANIFEST_VERSION_KEY = "version"
IAS_APP_CONFIGS_KEY = "appConfigs"
IAS_MANIFEST_VERSION = 1

# Selector fields this SDK cannot evaluate and accepts as unconstrained.
# tenantIds has no source in this SDK yet; service* describes a hosted service
# and does not apply to an in-process SDK.
IGNORED_SELECTOR_FIELDS = frozenset({"tenantIds", "service", "serviceVersion", "serviceVersionExclude"})


class PolicyError(ValueError):
    """The document is not a policy this SDK can use."""


class _Absent:
    """Sentinel for a key that the document did not mention at all."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self):
        return False

    def __repr__(self):
        return "ABSENT"


ABSENT = _Absent()


def optional(node, key):
    """Returns ABSENT when the key is missing, otherwise its value or None."""
    if not isinstance(node, dict):
        raise PolicyError("expected an object, got {}".format(type(node).__name__))
    return node[key] if key in node else ABSENT


def merge_patch(target, patch):
    """Applies an RFC 7386 JSON Merge Patch.

    Used for the SDK-specific fragment keys, whose shape this SDK does not
    know. A null member deletes the corresponding member of the target.
    """
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    merged = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = merge_patch(merged.get(key), value)
    return merged


def merge_optional(current, other, merger=None):
    """Applies the three-way optionality rule; see the module docstring.

    merger folds two present values together. Pass None for scalars, which are
    simply replaced.
    """
    if other is ABSENT:
        return current
    if other is None:
        return ABSENT
    if current is ABSENT or current is None:
        # Copied, not aliased: adopting the document's own object would let
        # the next fragment's merge mutate the document in place, and
        # effective_fragment would stop being idempotent.
        return copy.deepcopy(other)
    if merger is None:
        return other
    merger(current, other)
    return current


def _as_uint(value, name):
    """Returns an unsigned 64-bit integer, rejecting bools.

    JSON true is a Python bool and bool subclasses int, so without the
    explicit check {"deviceIdSample": true} would read as a 1% sample. The
    upper bound is the schema's; see UINT64_MAX.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError("{} must be a non-negative integer, got {!r}".format(name, value))
    if value < 0 or value > UINT64_MAX:
        raise PolicyError("{} must be an integer in [0, 2**64), got {!r}".format(name, value))
    return value


def _as_str(value, name):
    if not isinstance(value, str):
        raise PolicyError("{} must be a string, got {!r}".format(name, value))
    return value


def _as_str_list(value, name):
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise PolicyError("{} must be an array of strings, got {!r}".format(name, value))
    for item in value:
        if not isinstance(item, str):
            raise PolicyError("{} entries must be strings, got {!r}".format(name, item))
    return list(value)


class Endpoint:
    """Where and how to upload.

    RFD-0031: "The absence of an endpoint implies that the agent must not
    upload, i.e. the agent has been retired."
    """

    def __init__(self, protocol="", backoff=DEFAULT_UPLOAD_BACKOFF_SECONDS, base_url=""):
        self.protocol = protocol
        self.backoff = backoff
        self.base_url = base_url

    @classmethod
    def from_json(cls, node):
        protocol = optional(node, "protocol")
        backoff = optional(node, "backoff")
        base_url = optional(node, "baseUrl")
        return cls(
            protocol="" if protocol is ABSENT or protocol is None else _as_str(protocol, "protocol"),
            backoff=(
                DEFAULT_UPLOAD_BACKOFF_SECONDS if backoff is ABSENT or backoff is None else _as_uint(backoff, "backoff")
            ),
            base_url="" if base_url is ABSENT or base_url is None else _as_str(base_url, "baseUrl"),
        )

    def merge(self, other):
        """Replaces wholesale, rather than field by field.

        Deliberate, and the most surprising rule in the schema: a later
        fragment supplying an _endpoint without a backoff resets the backoff
        to the default rather than inheriting the earlier one. An endpoint is
        a whole destination, not a bag of settings.
        """
        self.protocol = other.protocol
        self.backoff = other.backoff
        self.base_url = other.base_url

    def is_usable(self):
        return bool(self.base_url) and self.protocol.casefold() == SKR_V2_PROTOCOL

    def __repr__(self):
        return "Endpoint(protocol={!r}, backoff={!r}, base_url={!r})".format(self.protocol, self.backoff, self.base_url)


class Retention:
    """How much collected data to keep on disk, and for how long.

    age and raw_files_age are in seconds; the cache values are in megabytes.
    Every field is independently optional, because Retention merges field by
    field.
    """

    # json key -> attribute
    FIELDS = {
        "age": "age",
        "cache": "cache",
        "minFreeDiskSpace": "min_free_disk_space",
        "rawFilesCache": "raw_files_cache",
        "rawFilesAge": "raw_files_age",
    }

    def __init__(self):
        self.age = ABSENT
        self.cache = ABSENT
        self.min_free_disk_space = ABSENT
        self.raw_files_cache = ABSENT
        self.raw_files_age = ABSENT

    @classmethod
    def from_json(cls, node):
        retention = cls()
        for key, attribute in cls.FIELDS.items():
            value = optional(node, key)
            if value is ABSENT or value is None:
                # null stays None so a merge can tell "erase this" from "this
                # was never mentioned".
                setattr(retention, attribute, value)
            else:
                setattr(retention, attribute, _as_uint(value, key))
        return retention

    def merge(self, other):
        """Merges field by field, unlike Endpoint.

        A later fragment can change one number without restating the rest,
        and a null erases just that one.
        """
        for attribute in self.FIELDS.values():
            merged = merge_optional(getattr(self, attribute), getattr(other, attribute))
            setattr(self, attribute, merged)

    def get(self, key, default=None):
        """Returns the value for a json key, or default if absent or null."""
        attribute = self.FIELDS[key]
        value = getattr(self, attribute)
        if value is ABSENT or value is None:
            return default
        return value

    def __repr__(self):
        return "Retention({})".format(
            ", ".join("{}={!r}".format(key, getattr(self, attribute)) for key, attribute in self.FIELDS.items())
        )


def _retention_overrides(node):
    """Returns the retention keys of one appConfigs entry, validated.

    A key outside Retention.FIELDS, or a value that is not an unsigned
    integer, is dropped rather than rejecting the document: by the time this
    is read the policy has already been parsed and applied, and refusing it
    here would retire the application over a field a newer service added.

    Args:
        node (dict): One application's appConfigs entry.

    Returns:
        dict: json key -> unsigned integer, empty when there is nothing usable.
    """
    overrides = {}
    if not isinstance(node, dict):
        log.warning("an {} entry is not an object, ignoring it".format(IAS_APP_CONFIGS_KEY))
        return overrides
    for key, value in node.items():
        if key not in Retention.FIELDS:
            log.warning("unknown {} field {}, ignoring it".format(IAS_APP_CONFIGS_KEY, key))
            continue
        try:
            overrides[key] = _as_uint(value, key)
        except PolicyError as e:
            log.warning("ignoring {} field {}: {}".format(IAS_APP_CONFIGS_KEY, key, e))
    return overrides


def _fold_app_config_keys(manifest):
    """Case-folds the appConfigs keys of one fragment's ias section.

    A GUID names the same application whatever case it is written in, but the
    fragment merge matches keys literally. Folding before the merge is what
    lets a later fragment patch or remove an entry an earlier one spelled in
    another case.

    Args:
        manifest (dict): One fragment's SDK-specific keys.

    Returns:
        dict: The same keys, with any appConfigs map re-keyed. The argument
        itself when there is no map to fold.
    """
    section = manifest.get(IAS_MANIFEST_KEY)
    if not isinstance(section, dict):
        return manifest
    configs = section.get(IAS_APP_CONFIGS_KEY)
    if not isinstance(configs, dict):
        return manifest
    folded = dict(section)
    folded[IAS_APP_CONFIGS_KEY] = {str(key).casefold(): value for key, value in configs.items()}
    patched = dict(manifest)
    patched[IAS_MANIFEST_KEY] = folded
    return patched


class IasManifest:
    """This SDK's own section of a policy fragment.

    Carries the closed allow list of the applications the policy supports. A
    section this SDK cannot read is reported as listing nobody rather than
    everybody, so a parse failure cannot open the list.

    policy documentation:
      RFD-0194, frameworks.telemetry.skylight-ridge.rfd
    """

    def __init__(self, app_configs):
        # Folded keys. A GUID names the same application whatever case it is
        # written in.
        self.app_configs = app_configs

    @classmethod
    def from_fragment(cls, fragment):
        """Returns the ias manifest an effective fragment carries, or None.

        Args:
            fragment (Fragment): The merge of every applicable fragment. Its
                SDK-specific keys are where the manifest lives.

        Returns:
            IasManifest|None: None when the manifest is absent, is not an
            object, states a version this SDK does not know, or carries no
            usable appConfigs map. Every one of those means no application is
            supported.
        """
        sections = getattr(fragment, "manifest", None)
        if not isinstance(sections, dict):
            return None
        node = sections.get(IAS_MANIFEST_KEY)
        if not isinstance(node, dict):
            log.info("the policy in effect has no usable {} section".format(IAS_MANIFEST_KEY))
            return None

        version = node.get(IAS_MANIFEST_VERSION_KEY)
        # json true is a Python bool and bool subclasses int, so without the
        # explicit check true == 1 would pass as the known version.
        if isinstance(version, bool) or version != IAS_MANIFEST_VERSION:
            log.error(
                "the policy's {} section is version {!r}, which this SDK cannot read".format(IAS_MANIFEST_KEY, version)
            )
            return None

        configs = node.get(IAS_APP_CONFIGS_KEY)
        if not isinstance(configs, dict):
            log.error(
                "the policy's {}.{} is not an object, got {!r}".format(IAS_MANIFEST_KEY, IAS_APP_CONFIGS_KEY, configs)
            )
            return None

        return cls({str(key).casefold(): value for key, value in configs.items()})

    def app_config(self, app_id):
        """Returns this application's retention overrides, or None.

        Args:
            app_id (str): The application's own id, as configured.

        Returns:
            dict|None: The overrides, empty when the application is listed
            with nothing to override. None means it is not listed at all,
            which is a different answer: the application is unsupported.
        """
        if str(app_id).casefold() not in self.app_configs:
            return None
        return _retention_overrides(self.app_configs[str(app_id).casefold()])

    def __repr__(self):
        return "IasManifest(appConfigs={})".format(sorted(self.app_configs))


class Selector:
    """Criteria deciding whether a policy or a fragment applies to a device.

    Absent and null fields match, empty arrays match, array values are ORed,
    and every field that is present must pass. Exclusion fields are checked
    after their inclusion counterpart, so an excluded device fails even when
    the inclusion list admitted it.
    """

    SAMPLE_FIELDS = ("deviceIdSample", "deviceIdSeed", "userIdSample", "userIdSeed")
    LIST_FIELDS = (
        "tenantIds",
        "os",
        "osVersion",
        "osVersionExclude",
        "osSku",
        "cpuSignature",
        "agent",
        "agentVersion",
        "agentVersionExclude",
        "service",
        "serviceVersion",
        "serviceVersionExclude",
    )

    def __init__(self, fields=None):
        # ABSENT and null both read as "no constraint". A selector is never
        # merged, unlike Retention, so the distinction carries no meaning here
        # (RFD-0031: "absent or null fields match").
        self.fields = fields or {}

    @classmethod
    def from_json(cls, node):
        if not isinstance(node, dict):
            raise PolicyError("a selector must be an object, got {!r}".format(node))
        fields = {}
        for key, value in node.items():
            if value is None:
                continue
            if key in IGNORED_SELECTOR_FIELDS:
                # Accepted so the document validates, but never evaluated.
                log.info("selector field {} is not evaluated by this SDK".format(key))
                continue
            if key in cls.SAMPLE_FIELDS:
                fields[key] = _as_uint(value, key)
            elif key in cls.LIST_FIELDS:
                fields[key] = _as_str_list(value, key)
            else:
                # A field from a newer schema. Treated as unconstrained rather
                # than failing the match, so adding a field cloud-side does
                # not silently retire every Python agent.
                log.warning("unknown selector field {}, ignoring it".format(key))
        return cls(fields)

    def _get(self, key, default=None):
        return self.fields.get(key, default)

    def matches(self, ctx, where="selector"):
        """Reports whether every constraint this selector states holds for ctx.

        Args:
            ctx (SelectorContext): The device facts to evaluate against.
            where (str): Names this selector in the log. A global selector
                rejects the whole policy while a fragment's only skips that
                fragment, so the two must not read alike.

        Returns:
            bool: True if every constraint holds.
        """
        # Device sampling is always evaluated, defaulting to the whole
        # population, so an absent deviceIdSample still admits an unknown
        # device id. User sampling is only evaluated when a user id exists.
        # That asymmetry is what the other agents do; the RFD is silent.
        if not is_sampled_guid(ctx.device_id, self._get("deviceIdSample", 100), self._get("deviceIdSeed", 0)):
            log.info("{} does not match: device id is not in the sample".format(where))
            return False

        if ctx.user_id and not is_sampled_guid(ctx.user_id, self._get("userIdSample", 100), self._get("userIdSeed", 0)):
            log.info("{} does not match: user id is not in the sample".format(where))
            return False

        for key, actual in (
            ("os", ctx.os),
            ("osSku", ctx.os_sku),
            ("agent", ctx.agent),
        ):
            values = self._get(key)
            if values is not None and not is_empty_or_contains(values, actual):
                log.info("{} does not match: {} {!r} not in {}".format(where, key, actual, values))
                return False

        for key, actual in (
            ("osVersion", ctx.os_version),
            ("agentVersion", ctx.agent_version),
        ):
            values = self._get(key)
            if values and not has_version_match(values, actual):
                log.info("{} does not match: {} {!r} not in {}".format(where, key, actual, values))
                return False

        for key, actual in (
            ("osVersionExclude", ctx.os_version),
            ("agentVersionExclude", ctx.agent_version),
        ):
            values = self._get(key)
            if values and has_version_match(values, actual):
                log.info("{} does not match: {} {!r} excluded by {}".format(where, key, actual, values))
                return False

        signatures = self._get("cpuSignature")
        if signatures is not None:
            signature = ctx.cpu_signature_str
            # Either the whole signature, or it with the stepping trimmed off.
            if not is_empty_or_contains(signatures, signature) and not contains_prefix(
                signatures, signature, CPU_SIGNATURE_NO_STEPPING
            ):
                log.info("{} does not match: cpuSignature {!r} not in {}".format(where, signature, signatures))
                return False

        return True

    def __repr__(self):
        return "Selector({!r})".format(self.fields)


class Fragment:
    """One entry of the fragments array, or the merge of several."""

    def __init__(self, endpoint=ABSENT, retention=ABSENT, selector=ABSENT, manifest=None):
        self.endpoint = endpoint
        self.retention = retention
        self.selector = selector
        # The SDK-specific keys, carried but not interpreted.
        self.manifest = manifest if manifest is not None else {}

    @classmethod
    def from_json(cls, node):
        if not isinstance(node, dict):
            raise PolicyError("a fragment must be an object, got {!r}".format(node))

        endpoint = optional(node, ENDPOINT_KEY)
        if endpoint is not ABSENT and endpoint is not None:
            endpoint = Endpoint.from_json(endpoint)

        retention = optional(node, RETENTION_KEY)
        if retention is not ABSENT and retention is not None:
            retention = Retention.from_json(retention)

        selector = optional(node, SELECTOR_KEY)
        if selector is not ABSENT and selector is not None:
            selector = Selector.from_json(selector)

        manifest = {key: value for key, value in node.items() if key not in (ENDPOINT_KEY, RETENTION_KEY, SELECTOR_KEY)}
        return cls(endpoint=endpoint, retention=retention, selector=selector, manifest=_fold_app_config_keys(manifest))

    def label(self, index=None):
        """Returns how this fragment names itself in a log line.

        The uuid is how the policy author identifies the fragment on their
        side, so quoting it makes a skipped fragment findable in the document
        that produced it.
        """
        uuid = self.manifest.get("uuid")
        name = "fragment" if index is None else "fragment {}".format(index)
        return "{} ({})".format(name, uuid) if uuid else name

    def applies_to(self, ctx, where=None):
        """Reports whether this fragment applies. No selector means it does."""
        if self.selector is ABSENT or self.selector is None:
            return True
        return self.selector.matches(ctx, where or "{} selector".format(self.label()))

    def merge(self, other):
        """Folds another fragment into this one.

        The selector is deliberately not merged: an effective fragment is the
        result of selection, so it no longer has criteria of its own.
        """
        self.endpoint = merge_optional(self.endpoint, other.endpoint, Endpoint.merge)
        self.retention = merge_optional(self.retention, other.retention, Retention.merge)
        # One merge_patch over the whole manifest, not per key: a null must
        # delete whether or not the key was inherited, and patching key by key
        # made a null on an *absent* key insert a literal null. merge_patch
        # also copies, so nothing is aliased back to the document.
        self.manifest = merge_patch(self.manifest, other.manifest)

    def get_endpoint(self):
        return self.endpoint if isinstance(self.endpoint, Endpoint) else None

    def get_retention(self):
        return self.retention if isinstance(self.retention, Retention) else None

    def __repr__(self):
        return "Fragment(endpoint={!r}, retention={!r}, selector={!r}, manifest={!r})".format(
            self.endpoint, self.retention, self.selector, self.manifest
        )


class PolicyDocument:
    """A parsed and validated v3 policy document."""

    def __init__(self, version, id, ts, expiration_seconds, global_selector, fragments):
        self.version = version
        self.id = id
        self.ts = ts
        self.expiration_seconds = expiration_seconds
        self.global_selector = global_selector
        self.fragments = fragments

    @classmethod
    def from_json(cls, doc):
        if not isinstance(doc, dict):
            raise PolicyError("a policy must be an object, got {!r}".format(doc))

        header = optional(doc, HEADER_KEY)
        if header is ABSENT or not isinstance(header, dict):
            raise PolicyError("the policy has no {} object".format(HEADER_KEY))

        version = optional(header, HEADER_VERSION_KEY)
        if version is ABSENT:
            raise PolicyError("the policy header has no version")
        version = _as_uint(version, HEADER_VERSION_KEY)
        # Checked before expiration in particular: that key changed units
        # between v2 (days) and v3 (seconds), so a v2 document read as v3
        # would look like a one second policy rather than a one day one.
        if version != POLICY_VERSION:
            raise PolicyError("unsupported policy document version {}".format(version))

        policy_id = optional(header, HEADER_ID_KEY)
        if policy_id is ABSENT or policy_id is None:
            raise PolicyError("the policy header has no id")
        policy_id = _as_str(policy_id, HEADER_ID_KEY)

        ts = optional(header, HEADER_TS_KEY)
        ts = 0 if ts is ABSENT or ts is None else _as_uint(ts, HEADER_TS_KEY)

        expiration = optional(doc, EXPIRATION_KEY)
        if expiration is ABSENT or expiration is None:
            raise PolicyError("the policy has no expiration")
        expiration = _as_uint(expiration, EXPIRATION_KEY)

        global_selector = optional(doc, GLOBAL_SELECTOR_KEY)
        if global_selector is not ABSENT and global_selector is not None:
            global_selector = Selector.from_json(global_selector)

        fragments = optional(doc, FRAGMENTS_KEY)
        if fragments is ABSENT or fragments is None:
            fragments = []
        elif not isinstance(fragments, list):
            raise PolicyError("{} must be an array, got {!r}".format(FRAGMENTS_KEY, fragments))
        else:
            fragments = [Fragment.from_json(fragment) for fragment in fragments]

        return cls(
            version=version,
            id=policy_id,
            ts=ts,
            expiration_seconds=expiration,
            global_selector=global_selector,
            fragments=fragments,
        )

    def is_applicable(self, ctx):
        """Reports whether a global selector admits this device.

        RFD-0031: a non-matching global selector rejects the policy entirely,
        leaving the SDK with no policy rather than one granting nothing.
        """
        if self.global_selector is ABSENT or self.global_selector is None:
            return True
        return self.global_selector.matches(ctx, "the policy's global selector")

    def effective_fragment(self, ctx):
        """Merges the applicable fragments, in document order.

        Document order, not `priority` order: RFD-0031 defines the merge as
        array order, and sorting would change which fragment wins a conflict.
        """
        effective = Fragment()
        for index, fragment in enumerate(self.fragments):
            if fragment.applies_to(ctx, "{} selector".format(fragment.label(index))):
                effective.merge(fragment)
        return effective

    def __repr__(self):
        return "PolicyDocument(version={!r}, id={!r}, expiration_seconds={!r}, fragments={})".format(
            self.version, self.id, self.expiration_seconds, len(self.fragments)
        )
