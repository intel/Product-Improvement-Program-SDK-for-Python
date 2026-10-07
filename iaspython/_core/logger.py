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

import logging

logger = logging.getLogger("telemetry")
logger.addHandler(logging.NullHandler())


class TelemetryLogger:
    def __init__(self):
        self.formatter = logging.Formatter(
            "%(asctime)s %(levelname)-7s [%(filename)s:%(lineno)d] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        logger.setLevel(logging.DEBUG)

    def set_console(self, level):
        sh = logging.StreamHandler()
        sh.setFormatter(self.formatter)
        logger.addHandler(sh)
        sh.setLevel(level)

    def set_file(self, level, logfile):
        fh = logging.FileHandler(logfile)
        fh.setFormatter(self.formatter)
        logger.addHandler(fh)
        fh.setLevel(level)
