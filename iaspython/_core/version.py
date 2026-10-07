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

# The name this SDK is published under, which importlib_metadata looks the
# running version up by. Must match the pyproject name, or Telemetry.__init__
# raises PackageNotFoundError on its first line.
#
# Not free to rename: the policy service matches this string as the `agent`
# selector, so a change would break policy matching server side without
# failing anywhere visible here.
DISTRIBUTION_NAME = "IasPython"

# Deliberately no __version__ constant. The version is the installed
# distribution's, read by Telemetry.__init__ and returned by
# get_api_version(), so it cannot fall behind what the pipeline shipped.
