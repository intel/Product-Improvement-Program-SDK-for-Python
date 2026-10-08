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

import ctypes
import locale
import os
import platform
import plistlib
import sys
import time
from datetime import datetime
from pathlib import Path

import cpuinfo
import psutil

if sys.platform == "win32":
    from winreg import *

if sys.platform == "darwin":
    import ctypes.util

from iaspython._core.logger import logger as log


class SystemInfo:
    # cpuinfo.get_cpu_info() shells out and costs about two seconds a call,
    # and cannot change while the process lives, so it is shared by every
    # SystemInfo rather than memoized per instance.
    _cpu_info_shared = None

    def __init__(self):
        self.installdate = 0
        # bios information
        self.ssku = ""
        self.sysv = ""
        self.biosv = ""
        # manufacturer information
        self.manu = ""
        self.sku = ""
        # cpu information
        self.rev = ""
        self.brand = ""
        # None means "not computed yet". 0 is a real answer: unknown.
        self.cpusig = None
        # os name
        self.osn = ""
        self.osv = ""
        # Policy selector variants, which the schema wants in different shapes
        # than the telemetry payload does.
        self.osv_numeric = ""
        self.osedition = ""

    def _read_file(self, path):
        data = ""
        try:
            if os.path.exists(path) and os.access(path, os.R_OK):
                with open(path) as f:
                    data = f.read().strip()
        except IOError as e:
            log.error("I/O error: {}".format(e))
        return data

    # /usr/lib/os-release is the vendor copy, read when the machine has no
    # /etc override; both are defined by the os-release spec.
    OS_RELEASE_PATHS = ("/etc/os-release", "/usr/lib/os-release")

    def _read_os_release(self, paths=None):
        """Returns the os-release key/value pairs as a dict, or empty.

        Parsed rather than sourced. The file is shell syntax, but none of the
        keys read from it (PRETTY_NAME, ID, VERSION_ID) need quote or escape
        handling beyond stripping the surrounding quotes.

        Tolerant of lines it does not understand: osSku comes from here, and
        the policy fetch fails outright without it.
        """
        os_release_info = {}
        for candidate in paths or self.OS_RELEASE_PATHS:
            path = Path(candidate)
            if not path.exists():
                continue
            with path.open() as infile:
                for line in infile:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    os_release_info[key.strip()] = value.strip().strip('"').strip("'")
            break
        return os_release_info

    SYSTEM_VERSION_PLIST = "/System/Library/CoreServices/SystemVersion.plist"

    def _read_system_version_plist(self, path=None):
        """Returns the macOS SystemVersion.plist as a dict.

        Split out like _read_os_release, as the one part of the Darwin branch
        that touches the filesystem, so a test can serve a known document.
        """
        with open(path or self.SYSTEM_VERSION_PLIST, "rb") as infile:
            return plistlib.load(infile, fmt=plistlib.FMT_XML)

    def _get_installdate(self):
        if self.installdate == 0:
            if sys.platform == "win32":
                try:
                    key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    with OpenKey(HKEY_LOCAL_MACHINE, key, access=KEY_READ | KEY_WOW64_64KEY) as key:
                        self.installdate, _ = QueryValueEx(key, "InstallDate")
                except Exception as e:
                    log.error("Could not read the InstallDate from the registry, error: {}".format(e))
            elif "linux" in sys.platform:
                path = "/lost+found"
                if os.path.exists(path):
                    self.installdate = int(os.stat(path).st_ctime)
            elif sys.platform == "darwin":
                path = "/var/db/.AppleSetupDone"
                if os.path.exists(path):
                    self.installdate = int(os.stat(path).st_ctime)
        return self.installdate

    def _get_osinfo(self):
        if self.osn:
            return self.osn, self.osv

        if platform.system() == "Windows":
            try:
                _, version, *_ = platform.win32_ver()
                major, _, build = map(int, version.split("."))
                with OpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") as key:
                    osname, _ = QueryValueEx(key, "ProductName")
                    ubr, _ = QueryValueEx(key, "UBR")
                    try:
                        # The policy selector's osSku, in its own try so a
                        # machine without EditionID still reports the name and
                        # version, which are telemetry wire fields.
                        edition, _ = QueryValueEx(key, "EditionID")
                        self.osedition = edition.lower()
                    except Exception as e:
                        log.info("Could not read the EditionID from the registry, error: {}".format(e))

                if major == 10 and ((build == 22000 and ubr >= 1) or build > 22000):
                    osname = osname.replace("10", "11")
                self.osn = osname
                self.osv = f"v{version}.{ubr}"
                # osVersion matching expects four components and no "v".
                self.osv_numeric = f"{version}.{ubr}"
            except Exception as e:
                log.error("Could not read the os name or version, error: {}".format(e))
        elif platform.system() == "Linux":
            try:
                os_release_info = self._read_os_release()
                self.osn = os_release_info.get("PRETTY_NAME", "")
                # ID is the closest Linux analogue of the Windows EditionID:
                # the short, version-free product token. Not PRETTY_NAME,
                # which carries the release and would make "ubuntu 24.04 lts"
                # and "ubuntu 24.04.1 lts" two SKUs for one fleet.
                self.osedition = os_release_info.get("ID", "").lower()
                # VERSION_ID, not the kernel release: a policy is written
                # against the distro release, never against
                # "6.18.33.2-microsoft-standard-WSL2". The payload's osv keeps
                # the kernel release, which is its established wire value.
                self.osv_numeric = os_release_info.get("VERSION_ID", "")
            except Exception as e:
                log.error("failed to load os info, error: {}".format(e))
        elif platform.system() == "Darwin":
            try:
                sysver_doc = self._read_system_version_plist()
                self.osn = sysver_doc["ProductName"]
                self.osv = sysver_doc["ProductVersion"]
                # No edition to read on macOS, so the osSku is the product
                # itself. Lowercasing ProductName would report "mac os x" on
                # releases old enough to spell it that way.
                self.osedition = "macos"
            except Exception as e:
                log.error("failed to load os info, error: {}".format(e))

        self.osn = platform.system() if not self.osn else self.osn
        self.osv = platform.release() if not self.osv else self.osv
        # Off Windows the selector's osVersion is the OS release, not a
        # four-part build number, so a pattern needs as many components as the
        # platform reports -- two for "26.04". With no release at all this
        # falls back to the payload's osv, which satisfies no pattern.
        self.osv_numeric = self.osv_numeric or self.osv
        # osSku is a required policy-fetch parameter and the service rejects an
        # empty one, which would cost the device its whole policy rather than
        # just its osSku selectors. The os name is what the os-release spec
        # defaults a missing ID to, and keeps an unrecognized platform able to
        # fetch.
        self.osedition = self.osedition or platform.system().lower()

        return self.osn, self.osv

    def get_os_type(self):
        """Returns the os as the policy selector names it: windows/linux/darwin."""
        return platform.system().lower()

    def get_os_version_numeric(self):
        """Returns the os version a policy selector is matched against.

        On Windows, the payload's osv without its "v". Elsewhere the OS
        release (VERSION_ID, or ProductVersion on macOS), deliberately not the
        payload's osv, which carries the kernel release.

        Kept separate rather than derived, because osv is a telemetry wire
        field and must not change shape.
        """
        self._get_osinfo()
        return self.osv_numeric

    def get_os_edition(self):
        """Returns the policy selector's osSku, lowercased.

        A Windows EditionID ("enterprise"), a Linux distribution ID
        ("ubuntu"), or "macos". Never empty: the service rejects a policy
        fetch that sends it empty.

        Off Windows the convention is this SDK's own -- other agents report
        this only on Windows, and RFD-0194 leaves Linux distros open. The
        matching release is get_os_version_numeric.
        """
        self._get_osinfo()
        return self.osedition

    def _cpu_info(self):
        # Fetched once per process. See _cpu_info_shared.
        if SystemInfo._cpu_info_shared is None:
            SystemInfo._cpu_info_shared = cpuinfo.get_cpu_info()
        return SystemInfo._cpu_info_shared

    @staticmethod
    def _pack_cpu_signature(family, model, stepping):
        """Rebuilds CPUID leaf 1 EAX from py-cpuinfo's decoded fields.

        The policy selector compares against the raw signature, but py-cpuinfo
        exposes only the *display* family and model, with the extended bits
        already folded in. This reverses that: family 6, model 142, stepping
        12 packs back to 0x806EC, whose stepping-trimmed form is the "0x806e"
        policies are written against.

        The processor type bits (13:12) are not recoverable and stay zero; no
        known selector uses them.
        """
        family_id = 15 if family >= 15 else family
        extended_family = family - 15 if family >= 15 else 0
        # Keyed on the *base* family, not the display family: a display family
        # above 15 still has a base family of 15, and testing the display
        # value would silently drop the model's high nibble.
        extended_model = (model >> 4) & 0xF if family_id in (6, 15) else 0
        return (
            (extended_family & 0xFF) << 20
            | extended_model << 16
            | (family_id & 0xF) << 8
            | (model & 0xF) << 4
            | (stepping & 0xF)
        )

    def get_cpu_signature(self):
        """Returns the policy selector's cpuSignature, or 0 when unknown.

        Only reported for Intel parts: a selector written against a signature
        means an Intel one, so a non-GenuineIntel vendor gives 0 rather than a
        number that could collide with one.
        """
        if self.cpusig is None:
            self.cpusig = 0
            try:
                info = self._cpu_info()
                if info.get("vendor_id_raw") == "GenuineIntel":
                    self.cpusig = self._pack_cpu_signature(info["family"], info["model"], info["stepping"])
                else:
                    log.info("non-Intel cpu, no cpu signature to report for policy matching")
            except Exception as e:
                log.error("Could not determine the cpu signature, error: {}".format(e))
        return self.cpusig

    def _get_biosinfo(self):
        if not self.ssku:
            self.ssku = "Unknown"
            self.sysv = "Unknown"
            self.biosv = "Unknown"
            if sys.platform == "win32":
                try:
                    key = r"HARDWARE\DESCRIPTION\System\BIOS"
                    with OpenKey(HKEY_LOCAL_MACHINE, key) as key:
                        self.ssku, _ = QueryValueEx(key, "SystemSKU")
                        self.sysv, _ = QueryValueEx(key, "SystemVersion")
                        biosvendor, _ = QueryValueEx(key, "BIOSVendor")
                        biosversion, _ = QueryValueEx(key, "BIOSVersion")
                        biosdate, _ = QueryValueEx(key, "BIOSReleaseDate")
                        self.biosv = "{} {}, {}".format(biosvendor, biosversion, biosdate)
                except Exception as e:
                    log.error("Could not read the bios version from the registry, error: {}".format(e))
            elif "linux" in sys.platform:
                biosvendor = self._read_file("/sys/devices/virtual/dmi/id/bios_vendor")
                biosversion = self._read_file("/sys/devices/virtual/dmi/id/bios_version")
                biosdate = self._read_file("/sys/devices/virtual/dmi/id/bios_date")
                if biosvendor and biosversion and biosdate:
                    self.biosv = "{} {}, {}".format(biosvendor, biosversion, biosdate)
            elif sys.platform == "darwin":
                pass
        return self.ssku, self.sysv, self.biosv

    def _get_manufacturer(self):
        if not self.manu:
            if sys.platform == "win32":
                try:
                    key = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
                    with OpenKey(HKEY_LOCAL_MACHINE, key) as key:
                        self.manu, _ = QueryValueEx(key, "SystemManufacturer")
                        self.sku, _ = QueryValueEx(key, "SystemProductName")
                except Exception as e:
                    log.error("Could not read the system information from the registry, error: {}".format(e))
            elif "linux" in sys.platform:
                self.manu = self._read_file("/sys/devices/virtual/dmi/id/board_vendor")
                self.sku = self._read_file("/sys/devices/virtual/dmi/id/board_name")
                if not self.sku:
                    # The DMI fallback for boards that expose a device tree
                    # instead, chiefly ARM. A device tree string property
                    # carries its NUL terminator, and .strip() does not remove
                    # it, so it would reach the payload's sku field.
                    self.sku = self._read_file("/proc/device-tree/model").strip("\x00").strip()
            elif sys.platform == "darwin":
                self.manu = "Apple"
                libc = ctypes.CDLL(ctypes.util.find_library("c"))
                size = ctypes.c_uint(0)
                hwmodel = "hw.model".encode("ascii")
                libc.sysctlbyname(hwmodel, None, ctypes.byref(size), None, 0)  # get buffer size
                buf = ctypes.create_string_buffer(size.value)
                libc.sysctlbyname(hwmodel, buf, ctypes.byref(size), None, 0)  # get model name to buffer
                self.sku = buf.value.decode()
            if not self.manu:
                self.manu = "Unknown"
            if not self.sku:
                self.sku = "Unknown"
        return self.manu, self.sku

    def _get_cpuinfo(self):
        if not self.brand:
            info = self._cpu_info()
            self.brand = info["brand_raw"]
            family = info["family"]
            model = info["model"]
            stepping = info["stepping"]
            rev = family << 16 | model << 8 | stepping
            self.rev = "{0:0{1}x}".format(rev, 7)
        return self.rev, self.brand

    def _get_resolution(self):
        if sys.platform == "win32":
            # SM_CXSCREEN and SM_CYSCREEN: the primary display in pixels.
            # Through ctypes rather than pywin32, which was a large binary
            # dependency with a post-install step for two integers, and which
            # forwarded to this same export. Reports the scaled resolution
            # unless the process is DPI aware, as pywin32 also did.
            user32 = ctypes.windll.user32
            return "{}x{}".format(user32.GetSystemMetrics(0), user32.GetSystemMetrics(1))
        else:
            return "0x0"

    def _get_locale(self):
        lc, _ = locale.getdefaultlocale()
        if not lc:
            lc = os.environ["LANG"]
            lc = lc.split(".")[0]
        lc = lc.replace("_", "-")
        return lc

    def get_systeminfo(self):
        info = {}
        info["tz"] = time.strftime("%z")
        info["ts"] = int(datetime.now().timestamp())
        # locale.setlocale(locale.LC_ALL, '')
        # (info['lc'], _) = locale.getlocale()
        info["lc"] = self._get_locale()
        info["osn"], info["osv"] = self._get_osinfo()
        machine = platform.machine()
        info["osb"] = 64 if "64" in machine else 32
        manu, sku = self._get_manufacturer()
        info["manu"] = manu
        info["sku"] = sku
        rev, brand = self._get_cpuinfo()
        info["cpub"] = brand
        info["cpur"] = rev
        mem = psutil.virtual_memory()
        info["mem"] = int(mem.total / 1024 / 1024)
        info["res"] = self._get_resolution()
        info["appb"] = 64 if sys.maxsize > 2**32 else 32
        ssku, sysv, biosv = self._get_biosinfo()
        info["ssku"] = ssku
        info["sysv"] = sysv
        info["biosv"] = biosv
        info["oobets"] = self._get_installdate()
        info["bkc"] = ""
        return info
