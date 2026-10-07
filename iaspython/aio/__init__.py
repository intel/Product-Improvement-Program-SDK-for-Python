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

"""Telemetry as coroutines, for applications running an event loop.

The same API as ``iaspython.sync``, except that everything touching the disk or
the network must be awaited -- ``attach``, ``attach_file``, ``flush`` and
``close``. ``record_event`` only touches memory and is not a coroutine.

Forgetting an ``await`` does not raise: Python creates the coroutine, never
runs it, and the record is silently never made.
"""

from iaspython._core.exceptions import TelemetryClosed, TelemetrySessionClosed
from iaspython._core.logger import TelemetryLogger
from iaspython.aio.session import TelemetrySession
from iaspython.aio.telemetry import Telemetry

__all__ = [
    "Telemetry",
    "TelemetrySession",
    "TelemetryClosed",
    "TelemetrySessionClosed",
    "TelemetryLogger",
]
