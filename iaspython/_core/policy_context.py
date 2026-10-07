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

"""The device facts a v3 policy selector is evaluated against.

A frozen dataclass of already-resolved primitives, so a test can build one in
a line without a registry, a CPU probe or a store folder. Everything that
touches the environment happens in build_selector_context, once per flush.

These are NOT the shapes the telemetry payload carries: the payload's osv is
"v10.0.22631.2861" and its cpur packs family/model/stepping differently. See
SystemInfo.get_os_version_numeric.
"""

import dataclasses

from iaspython._core.logger import logger as log
from iaspython._core.skr import SKR_SOURCE_NAME

# _core.telemetry imports no policy module, so this direction is safe.
from iaspython._core.telemetry import ZERO_UUID


@dataclasses.dataclass(frozen=True)
class SelectorContext:
    os: str = ""
    os_version: str = ""
    os_sku: str = ""
    cpu_signature: int = 0
    agent: str = ""
    agent_version: str = ""
    device_id: str | None = None
    user_id: str | None = None

    @property
    def cpu_signature_str(self):
        """Returns the signature as the policy spells it, e.g. "0x806ec".

        Four digits is a *minimum*, which is the form policies are written
        against; a signature below 0x10000 therefore has no distinct
        stepping-trimmed form.
        """
        return "0x{:04x}".format(self.cpu_signature)


def normalize_identity(guid):
    """Returns an id suitable for sampling, or None when there is not one.

    The all-zero guid maps to None deliberately: as a present guid it would
    hash to one fixed bucket, sampling every post_did="zero" install together,
    all in or all out. An unknown device id is never sampled, which is the
    honest reading of an anonymized one too.
    """
    if not guid or guid == ZERO_UUID:
        return None
    return guid


def build_selector_context(sdk_version, sysinfo, device_id=None, user_id=None):
    """Resolves the device facts a selector needs.

    agent_version is passed through as-is, and the package version has four
    components on purpose: version_match requires matching component counts,
    and every agent version in RFD-0031 is four, so a three-component version
    would silently fail every agentVersion selector.

    Padding here instead was rejected, because the same string is reported as
    the payload's sdkv and the record's source.version, so a policy written
    against "1.0.0.0" would select devices whose records say "1.0.0".
    """
    context = SelectorContext(
        os=sysinfo.get_os_type(),
        os_version=sysinfo.get_os_version_numeric(),
        os_sku=sysinfo.get_os_edition(),
        cpu_signature=sysinfo.get_cpu_signature(),
        agent=SKR_SOURCE_NAME,
        agent_version=str(sdk_version or ""),
        device_id=normalize_identity(device_id),
        user_id=normalize_identity(user_id),
    )
    log.debug("policy selector context: {}".format(context))
    return context
