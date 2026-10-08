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

"""In-App Telemetry, implemented entirely in Python.

The public API is ``iaspython.sync`` and ``iaspython.aio``. See the project
documentation for enablement details (what to instrument, how telemetry ids
are issued).
"""

# Read from the installed distribution, so this and the agentVersion the
# policy request sends are one number. Telemetry.get_api_version() answers the
# same question without needing an instance.
#
# PackageNotFoundError means a source checkout with nothing pip-installed,
# which is how the tests and samples run.
from importlib_metadata import PackageNotFoundError
from importlib_metadata import version as _distribution_version

from iaspython._core.version import DISTRIBUTION_NAME

try:
    __version__ = _distribution_version(DISTRIBUTION_NAME)
except PackageNotFoundError:
    __version__ = "0.0.0"
