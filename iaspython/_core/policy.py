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
from datetime import datetime, timedelta
from urllib.parse import urlencode

from iaspython._core import utils
from iaspython._core.logger import logger as log
from iaspython._core.policy_context import build_selector_context, normalize_identity
from iaspython._core.policy_schema import (
    DEFAULT_UPLOAD_BACKOFF_SECONDS,
    POLICY_VERSION,
    Fragment,
    IasManifest,
    PolicyDocument,
    PolicyError,
)
from iaspython._core.skr import accepted_etag, policy_request_headers, policy_useragent, resolve_ias_telemetry_id
from iaspython._core.store import resolved_store_folder
from iaspython._core.systeminfo import SystemInfo

# The base endpoint; the telemetry id is appended as a path segment.
# There is no trailing slash after the id.
POLICY_URL = "REDACTED"

# policy documentation:
#   RFD-0031, frameworks.telemetry.skylight-ridge.rfd

# The absolute expiry stamped into the cached copy on disk. The SDK's own
# bookkeeping, not part of the policy schema; the parser ignores unknown
# top-level keys.
EXPIRES_AT_KEY = "expire_epoch"

# The response ETag, stamped into the cached copy so the next fetch can
# revalidate rather than re-download.
ETAG_KEY = "etag"

NANOSECONDS = 1000000000

DEFAULT_BACKOFF_SECONDS = DEFAULT_UPLOAD_BACKOFF_SECONDS

# Used when the document's own expiration cannot be applied, so a document
# without a usable expiration still has a definite lifetime.
DEFAULT_EXPIRATION_SECONDS = 90 * 24 * 60 * 60

# Applied whenever the policy in effect states no retention value, including
# when there is no policy at all. Without these a device that never receives a
# usable policy would save a payload on every flush and never reap any of it.
# Ages are in seconds, caches in megabytes.
DEFAULT_RETENTION = {
    "age": 90 * 24 * 60 * 60,
    "cache": 64,
    "rawFilesAge": 10 * 24 * 60 * 60,
    "rawFilesCache": 2048,
}

MEGABYTE = 1024 * 1024


def _megabytes_to_bytes(value):
    return None if value is None else int(value) * MEGABYTE


def response_etag(headers):
    """Returns the ETag of a policy response, or None.

    Both clients return a case-insensitive mapping, but an error path can pass
    None, so the type is checked rather than assumed.
    """
    if not headers:
        return None
    try:
        etag = headers.get("ETag")
    except AttributeError:
        return None
    return accepted_etag(etag)


class PolicyBase:
    def __init__(self, config, http_client, sysinfo=None, ias_telemetry_id=None):
        self.config = config
        # Copied out, not re-read: the cache path must not move if the
        # application rewrites its own config dict.
        self.app_name = config["AppName"]
        # The instrumented application's id, looked up in the policy's
        # appConfigs allow list. Not the id the policy is fetched under.
        self.app_id = config["TelemetryId"]
        self.sdk_version = config.get("SdkVersion", "")
        # Shared by every application. Passed in by Telemetry; resolved here
        # when absent so a test can construct a PolicyBase on its own.
        self.ias_telemetry_id = ias_telemetry_id if ias_telemetry_id is not None else resolve_ias_telemetry_id()
        # Without the query string; policy_request_url() appends the device
        # facts, which change between flushes.
        self.policy_url = "{}/{}".format(POLICY_URL, self.ias_telemetry_id)
        self.http_client = http_client
        # Shared with Telemetry so the registry and cpu are read once; built
        # here when absent so a test can construct a PolicyBase on its own.
        self.sysinfo = sysinfo if sysinfo is not None else SystemInfo()

        store = resolved_store_folder(self.config)
        # Keyed on the application, not on the policy: every app caches its own
        # copy of the one shared document, beside the telemetry it gates. A
        # copy fetched under a different ias telemetry id fails the header
        # check and is discarded.
        self.local_policy_file = os.path.join(store, self.app_name, self.app_id, "policy.json")

        # The policy in effect; assigned only by a successful _process_policy.
        self.document = None
        self.effective = Fragment()
        self.expires_at = None
        self.expiration_seconds = 0

        # A good document whose global selector excludes this device is still
        # a current answer, and holds until it expires. This separates "does
        # not apply here" from "could not be fetched", which retries every
        # flush. The duration is kept beside the deadline for the same reason
        # is_expired keeps expiration_seconds: a clock that moves backwards.
        self.inapplicable_until = None
        self.inapplicable_seconds = 0

        self._device_id = None
        self._user_id = None
        self._context = None

        # The ETag of the document on disk, sent back as If-None-Match.
        self.etag = None

        # When this device last uploaded, in epoch seconds, or None if it never
        # has, in which case the parameter is omitted rather than sent as 1970.
        # The backoff is added in _next_upload_ns, not here.
        self.last_upload_s = None

    # -- device identity ---------------------------------------------------

    def set_identity(self, device_id, user_id):
        """Supplies the ids that sampling selectors are evaluated against.

        Called once per flush from the payload that was just built, so the
        policy and the payload can never disagree about who this device is.
        """
        device_id = normalize_identity(device_id)
        user_id = normalize_identity(user_id)
        if device_id == self._device_id and user_id == self._user_id:
            return

        self._device_id = device_id
        self._user_id = user_id
        self._context = None
        # Applicability may have rested on the ids that just changed, so it is
        # decided again. The cached file is still on disk, so this costs a read
        # at worst, not a download.
        self.inapplicable_until = None
        self.inapplicable_seconds = 0
        if self.document is not None:
            self._reselect()

    def _reselect(self):
        """Re-derives what was selected against the previous identity.

        The global selector is re-checked as well as the fragments, since it
        may sample on the ids that changed. The expiry is left alone:
        re-selecting is not a reload and must not extend the lifetime.
        """
        try:
            ctx = self.selector_context()
            if self.document.is_applicable(ctx):
                self.effective = self.document.effective_fragment(ctx)
                return
            log.info("the policy in effect no longer applies to this device, dropping it")
            # Still the service's current answer, so it holds until it expires.
            self.inapplicable_until = self.expires_at
            self.inapplicable_seconds = self.expiration_seconds
        except Exception as e:
            log.error("could not re-apply the policy after an identity change: {}: {}".format(type(e), e))
        self._clear_in_effect()

    def _clear_in_effect(self):
        """Leaves no policy in effect.

        All four fields describe one document and are cleared together: a
        leftover `effective` fragment would go on supplying an endpoint, a
        backoff and retention limits for a document no longer applied.
        """
        self.document = None
        self.effective = Fragment()
        self.expires_at = None
        self.expiration_seconds = 0

    def set_last_upload(self, timestamp):
        """Supplies when this device last uploaded, in epoch seconds.

        The backoff is deliberately not added here: on the first flush after a
        restart the policy is still unread, so there would be no backoff to
        add, and the request would report the device as free to upload now.

        Args:
            timestamp (int): Epoch seconds, or falsy if nothing has ever
                uploaded, in which case the parameter is left off the request.
        """
        self.last_upload_s = timestamp or None

    def _next_upload_ns(self):
        """Returns when this device may next upload, in nanoseconds, or None.

        Read while the request is built, after load_policy has put any cached
        document in effect, so the backoff reported is the one this client will
        go on to enforce.
        """
        if not self.last_upload_s:
            return None
        timestamp = self.last_upload_s + self.upload_backoff_seconds()
        # Whole seconds are scaled as an integer: a float64 runs out of
        # significant digits before nanoseconds on a present-day epoch, so
        # int(timestamp * NANOSECONDS) would silently round.
        seconds = int(timestamp)
        return seconds * NANOSECONDS + int(round((timestamp - seconds) * NANOSECONDS))

    def selector_context(self):
        if self._context is None:
            self._context = build_selector_context(self.sdk_version, self.sysinfo, self._device_id, self._user_id)
        return self._context

    # -- the fetch request -------------------------------------------------

    def policy_request_url(self):
        """Returns the fetch URL, device facts and all.

        The service selects on these facts, which is why RFD-0031 expects a
        policy to arrive as a single fragment with no _selector. They come from
        the same selector_context() the client evaluates _selector against.

        Device facts are sent unconditionally, even when empty; deviceId,
        userId and backOff are omitted when not known.
        """
        ctx = self.selector_context()
        params = {
            "agent": ctx.agent,
            "agentVersion": ctx.agent_version,
            "cpuSignature": ctx.cpu_signature_str,
            "os": ctx.os,
            "osSku": ctx.os_sku,
            "osVersion": ctx.os_version,
            # Required by the endpoint. This SDK is both agent and service, so
            # it reports itself twice rather than sending an empty value the
            # service would reject.
            "service": ctx.agent,
            "serviceVersion": ctx.agent_version,
        }
        # tenantIds belongs here too, but this SDK has no source for a tenant.
        if ctx.device_id:
            params["deviceId"] = ctx.device_id
        if ctx.user_id:
            params["userId"] = ctx.user_id
        next_upload_ns = self._next_upload_ns()
        if next_upload_ns is not None:
            params["backOff"] = str(next_upload_ns)
        return "{}?{}".format(self.policy_url, urlencode(sorted(params.items()), safe=","))

    def request_headers(self):
        """Headers for the policy GET, including revalidation when possible."""
        ctx = self.selector_context()
        return policy_request_headers(policy_useragent(ctx.agent, ctx.agent_version), self.etag)

    # -- expiry ------------------------------------------------------------

    def is_expired(self, now=None):
        """Reports whether no policy is in effect, or the one in effect is stale.

        Stale means past the expiry, or valid for longer than the document said
        it would be, which means the clock moved backwards since the fetch.
        """
        if self.document is None or self.expires_at is None:
            # A never-loaded policy has to read as expired, or the first flush
            # would upload with no policy at all.
            return True
        now = now if now is not None else datetime.now()
        if now > self.expires_at:
            return True
        # Compared in seconds, not as a timedelta: expiration_seconds is an
        # unbounded integer from the document, and timedelta(seconds=...)
        # raises OverflowError past about 2.7e14. The remaining lifetime is a
        # gap between two real datetimes, so it always fits.
        return (self.expires_at - now).total_seconds() > self.expiration_seconds

    def _persisted_expiry(self, doc):
        """Returns the absolute expiry a previous run stamped into the cache.

        Only read from a document off our own disk. A downloaded document
        carrying this key was likely authored from a copy-pasted cache file,
        and honoring it would make the document arrive already expired.
        """
        return doc.get(EXPIRES_AT_KEY) if isinstance(doc, dict) else None

    def _resolve_expiry(self, persisted, document):
        if persisted is not None:
            try:
                return datetime.fromtimestamp(persisted)
            except (OSError, OverflowError, TypeError, ValueError) as e:
                log.error("could not read the persisted policy expiry: {}".format(e))
        return self._expiry_from_now(document.expiration_seconds)

    def _expiry_from_now(self, seconds):
        """Returns `seconds` from now, or the default lifetime if it will not fit.

        An enormous expiration is a valid way to say "this answer stands", but
        timedelta(seconds=...) gives up around 2.7e14, and the OverflowError
        would surface in the host application's flush().
        """
        try:
            return datetime.now() + timedelta(seconds=seconds)
        except (OverflowError, OSError):
            log.error(
                "policy expiration {} is out of range, falling back to {} seconds".format(
                    seconds, DEFAULT_EXPIRATION_SECONDS
                )
            )
            return datetime.now() + timedelta(seconds=DEFAULT_EXPIRATION_SECONDS)

    # -- loading -----------------------------------------------------------

    def _parse_policy(self, doc):
        """Returns a PolicyDocument, or None if it can never be used here.

        Separate from _put_in_effect because the failures differ: a document
        that cannot be parsed or belongs to another product is worth throwing
        away, while one that merely does not apply to this device is good.

        Never raises. A bad response from the policy service must not surface
        inside the host application.
        """
        try:
            document = PolicyDocument.from_json(doc)
        except PolicyError as e:
            log.error("not a usable version {} policy document: {}".format(POLICY_VERSION, e))
            return None
        except Exception as e:
            # Deliberately broad: v3 parsing can raise TypeError,
            # AttributeError and more on a malformed document.
            log.error("could not process the policy document: {}: {}".format(type(e), e))
            return None

        ias_telemetry_id = str(self.ias_telemetry_id)
        if document.id.casefold() != ias_telemetry_id.casefold():
            log.error(
                "policy header id {} is not the IAS telemetry id {}, rejecting it".format(document.id, ias_telemetry_id)
            )
            return None

        return document

    def _put_in_effect(self, document, persisted_expiry=None):
        """Makes a parsed document the policy in effect, if it applies here.

        Args:
            document (PolicyDocument): The parsed document.
            persisted_expiry (int): The stamp a previous run left on the cached copy.
                Passed only by callers reading from disk; a caller that
                downloaded the document passes nothing and gets a fresh
                lifetime. See _persisted_expiry.

        Returns:
            tuple: (applied, expires_at). `applied` is False when the document
            is valid but its global selector excludes this device, in which
            case nothing is left in effect. `expires_at` is reported either
            way, and is returned rather than read off self because nothing is
            assigned unless the document is accepted.
        """
        try:
            ctx = self.selector_context()
            expires_at = self._resolve_expiry(persisted_expiry, document)

            if not document.is_applicable(ctx):
                log.info(
                    "the policy's global selector does not match this device; "
                    "it does not apply until {}".format(expires_at)
                )
                # Recorded so the SDK stops asking: "nothing" is still the
                # service's current answer. Distinct from a failed fetch.
                self.inapplicable_until = expires_at
                self.inapplicable_seconds = document.expiration_seconds
                # Whatever was in effect has been superseded. Leaving it would
                # let accept_not_modified revive it on the exclusion's next
                # revalidation. Only ever an expired document, since
                # load_policy does not download while one is current.
                self._clear_in_effect()
                return False, expires_at

            effective = document.effective_fragment(ctx)

            self.document = document
            self.effective = effective
            self.expiration_seconds = document.expiration_seconds
            self.expires_at = expires_at
            self.inapplicable_until = None
            self.inapplicable_seconds = 0
            log.info("policy loaded, expires {}".format(self.expires_at))
            return True, expires_at
        except Exception as e:
            log.error("could not apply the policy document: {}: {}".format(type(e), e))
            return False, None

    def _process_policy(self, doc):
        """Parses a policy document and, if it applies here, puts it in effect.

        Takes the document complete with any cache stamp, so a caller can hand
        it a whole cached file. accept_downloaded must not do that.
        """
        document = self._parse_policy(doc)
        if document is None:
            return False
        applied, _ = self._put_in_effect(document, self._persisted_expiry(doc))
        return applied

    def _inapplicable_answer_is_current(self, now=None):
        """Reports whether "this policy is not for you" is still the live answer.

        The two clauses are the ones is_expired applies to a policy in effect,
        for the same reasons. A deadline further out than the document was
        valid for means the clock moved backwards, and honoring it would
        suppress downloads for as long as the rollback lasts.
        """
        if self.inapplicable_until is None:
            return False
        now = now if now is not None else datetime.now()
        if now > self.inapplicable_until:
            return False
        return (self.inapplicable_until - now).total_seconds() <= self.inapplicable_seconds

    def should_download(self, now=None):
        """Reports whether it is worth asking the service for a policy.

        False while a policy is in effect and current, and also while a
        current document that does *not* apply to this device is cached, since
        asking again would only get the same answer. Only a failed fetch, or
        an expired answer of either kind, retries on the next flush.
        """
        if not self.is_expired(now):
            return False
        if self._inapplicable_answer_is_current(now):
            return False
        return True

    def accept_cached(self, doc):
        """Puts a cached document in effect when it is still usable.

        The file is discarded only when it can never be used -- a v2 document
        left by an older SDK, or one belonging to another product. A document
        that parses but does not apply here is kept: the exclusion may be by
        sampling seed rather than anything permanent.
        """
        document = self._parse_policy(doc)
        if document is None:
            self.etag = None
            self.discard_local_policy()
            return False

        # Read before the outcome is known: the etag is wanted precisely when
        # the cached document turns out to be expired, which returns False.
        # Checked as well as the downloaded one: the file is the SDK's, but
        # what is in it came off the network.
        self.etag = accepted_etag(doc.get(ETAG_KEY)) if isinstance(doc, dict) else None

        applied, _ = self._put_in_effect(document, self._persisted_expiry(doc))
        if not applied:
            return False
        return not self.is_expired()

    def accept_not_modified(self, doc):
        """Handles a 304: the service says the cached document is still current.

        Refreshes the lifetime of whatever the cached file put in memory and
        re-stamps `doc`, including the etag, so the caller can write it back.
        Without the refresh the document stays expired and the SDK revalidates
        on every flush; without the etag the next process cannot revalidate at
        all.

        Args:
            doc (dict): The cached document, re-stamped in place.

        Returns:
            bool: True when a policy is in effect afterwards.
        """
        # Checked first. _put_in_effect leaves nothing in effect when it
        # records an exclusion, so the two cannot both be set -- but the
        # exclusion is the more recent answer, and reviving a document over the
        # top of it is the expensive mistake.
        if self.inapplicable_until is not None:
            # Still a current answer, so its deadline moves out by the same
            # rule and through the same overflow guard.
            self.inapplicable_until = self._expiry_from_now(self.inapplicable_seconds)
            self._stamp(doc, self.inapplicable_until, self.etag)
            log.info("the policy still does not apply here, refreshed to {}".format(self.inapplicable_until))
            return False

        if self.document is not None:
            self.expires_at = self._resolve_expiry(None, self.document)
            self._stamp(doc, self.expires_at, self.etag)
            log.info("the policy is unchanged, expiry refreshed to {}".format(self.expires_at))
            return True

        # A 304 with nothing in memory is a service-side inconsistency: the
        # conditional request is only sent when there is a document to
        # revalidate.
        log.error("the service reports the policy unchanged, but there is no cached policy in memory")
        return False

    def refresh_would_lose_a_newer_policy(self, on_disk):
        """Reports whether writing a refreshed 304 document back would discard
        a newer one that reached the cache in the meantime.

        Two processes of the app revalidate the same cache file on their own
        schedules, so the other one can download and write a new document
        while this one's conditional request -- carrying the previous etag --
        is answered 304. Writing back would then lose the newer endpoint,
        retention and etag until the older document expires.

        This narrows the window to the gap between the re-read and the rename
        rather than closing it. Closing it needs a lock held across the read,
        the request and the write, which would serialize flushes between
        processes. The rename is atomic, so the worst case is a lost refresh,
        not corruption.

        Args:
            on_disk (dict): The document as the file holds it right now,
                re-read after the response arrived. Compared by etag, since
                that is the service's own name for a document version.

        Returns:
            bool: True if writing back would discard a newer document.
        """
        if not isinstance(on_disk, dict) or not on_disk:
            # Absent, unreadable, or not a document. The refreshed copy is
            # strictly better.
            return False
        return on_disk.get(ETAG_KEY) != self.etag

    def _stamp(self, doc, expires_at, etag=None):
        """Writes the SDK's own bookkeeping into a document bound for the cache."""
        if not isinstance(doc, dict):
            return
        if expires_at is not None:
            doc[EXPIRES_AT_KEY] = int(expires_at.timestamp())
        if etag:
            doc[ETAG_KEY] = etag
        else:
            doc.pop(ETAG_KEY, None)

    def accept_downloaded(self, doc, etag=None):
        """Reports whether a freshly downloaded document is worth caching.

        That includes one whose global selector excludes this device: caching
        it is what stops the SDK re-downloading the same answer every flush.
        Whether it is also *in effect* is answered by `not is_expired()`.

        The stamped expiry lets the next run tell how much lifetime is left;
        the etag lets the next fetch revalidate instead of re-downloading.
        """
        document = self._parse_policy(doc)
        if document is None:
            return False

        # No persisted expiry: this document just arrived, so its lifetime
        # starts now. The expiry comes from the return value rather than off
        # self, because an inapplicable document leaves self.expires_at None
        # and would reach disk with no expiry at all -- which the next process
        # reads as a document to download again, forever.
        _applied, expires_at = self._put_in_effect(document)
        self.etag = etag
        self._stamp(doc, expires_at, etag)
        return True

    def discard_local_policy(self):
        """Removes a cached document that could not be used.

        Chiefly the upgrade case: a v2 document left by an older SDK will
        never parse, and would be re-read and re-rejected on every flush.
        """
        try:
            if os.path.exists(self.local_policy_file):
                os.remove(self.local_policy_file)
                log.info("removed the unusable cached policy {}".format(self.local_policy_file))
        except OSError as e:
            log.error("could not remove {}: {}".format(self.local_policy_file, e))

    # -- accessors ---------------------------------------------------------

    def _endpoint(self):
        return self.effective.get_endpoint()

    def _app_config(self):
        """Returns this application's entry in the policy's allow list, or None.

        None means the application is not supported.
        """
        if self.document is None:
            return None
        manifest = IasManifest.from_fragment(self.effective)
        if manifest is None:
            return None
        return manifest.app_config(self.app_id)

    def is_app_supported(self):
        """Reports whether the policy lists the application the SDK is in.

        ias.appConfigs is a closed allow list: an application absent from it
        must not collect nor upload anything. That is a decision, not a
        failure, so the caller discards rather than retries.

        True when there is no policy at all, so that a device which is merely
        offline keeps what it has collected.

        Returns:
            bool: True when this application may collect.
        """
        if self.document is None:
            return True
        if self._app_config() is None:
            log.info("the policy does not list this application's ID {}".format(self.app_id))
            return False
        return True

    def is_retired(self):
        """Reports whether the policy in effect says not to upload at all.

        RFD-0031: "The absence of an endpoint implies that the agent must not
        upload, i.e. the agent has been retired." Separate from can_upload()
        because retirement is the only answer that justifies discarding
        collected data. An endpoint that is present but unusable is not
        retirement, and neither is having no policy at all.
        """
        if self.document is None:
            return False
        if self.config.get("CollectorUrl"):
            return False
        if self._endpoint() is not None:
            return False
        log.info("the policy provides no endpoint, this agent is retired")
        return True

    def can_upload(self):
        """Reports whether there is a usable destination for an upload.

        Two different situations answer False, and callers must not treat them
        alike -- is_retired() distinguishes them:

          * no endpoint at all: the agent is retired, nothing to retry, the
            data is discarded
          * an endpoint this SDK cannot use (unknown protocol, missing url, or
            a cleartext one): a later policy or SDK may be able to, so the
            data is kept as it is

        The only gate in front of the upload. get_telemetry_url() does not
        re-ask, and both flush paths call this before building the uploader.
        """
        collector_url = self.config.get("CollectorUrl")
        if collector_url:
            # Re-checked rather than trusted from validate_config: the config
            # is the caller's dict, held by reference, and an application that
            # changes this key afterwards must not reach a cleartext url.
            if not utils.is_tls_url(collector_url):
                log.error("the configured CollectorUrl is not https, refusing to upload to it")
                return False
            return True
        endpoint = self._endpoint()
        if endpoint is None:
            return False
        if not endpoint.is_usable():
            # The origin only: this baseUrl came out of a response body and
            # can carry a token or userinfo.
            log.warning(
                "the policy endpoint is not usable: protocol={!r} baseUrl={}".format(
                    endpoint.protocol, utils.url_origin(endpoint.base_url)
                )
            )
            return False
        # Checked separately from is_usable(), whose `protocol` is the SKR API
        # version (skr_v2) and says nothing about the transport. This baseUrl
        # came from a document fetched over the network.
        if not utils.is_tls_url(endpoint.base_url):
            log.error(
                "the policy endpoint is not https, refusing to upload to it: baseUrl={}".format(
                    utils.url_origin(endpoint.base_url)
                )
            )
            return False
        return True

    def get_telemetry_url(self):
        """Returns the upload base url. CollectorUrl overrides the policy's."""
        if self.config.get("CollectorUrl"):
            return self.config["CollectorUrl"]
        endpoint = self._endpoint()
        if endpoint is None or not endpoint.base_url:
            log.error("telemetry URL not found from the policy")
            raise PolicyError("the policy in effect has no upload endpoint")
        return endpoint.base_url

    def get_protocol(self):
        endpoint = self._endpoint()
        return endpoint.protocol if endpoint else ""

    def upload_backoff_seconds(self):
        """Returns the minimum gap between uploads, in seconds.

        An _endpoint that omits its backoff gets the one day default; in the
        v2 schema a missing value meant no throttling. An explicit zero still
        means no throttling.

        No endpoint at all also means no throttling, not the default: the only
        case that reaches here is a caller uploading to a configured
        CollectorUrl, whose destination the policy is not describing.
        """
        endpoint = self._endpoint()
        if endpoint is None:
            return 0
        return endpoint.backoff

    def _retention_value(self, key):
        # The application's entry is a merge patch onto the fragment's
        # _retention, so a key it states wins and the rest fall through.
        override = self._app_config()
        if override is not None and key in override:
            return override[key]
        retention = self.effective.get_retention()
        if retention is not None:
            value = retention.get(key)
            if value is not None:
                return value
        default = DEFAULT_RETENTION.get(key)
        if default is not None:
            log.info("retention.{} not found from the policy, using the default {}".format(key, default))
        return default

    def retention_age_seconds(self):
        return self._retention_value("age")

    def retention_cache_bytes(self):
        return _megabytes_to_bytes(self._retention_value("cache"))

    def retention_raw_files_age_seconds(self):
        return self._retention_value("rawFilesAge")

    def retention_raw_files_cache_bytes(self):
        return _megabytes_to_bytes(self._retention_value("rawFilesCache"))

    def retention_min_free_disk_bytes(self):
        """Parsed and reported, but not yet enforced anywhere.

        RFD-0031 makes this a floor on collection, so it belongs on the attach
        path in _core/session.py, not here on flush. Three things need settling
        first:

          * sessions are handed a store, not a policy
          * attachments can be created before any flush has loaded a policy
          * attach_file contracts to return a guid and raise ValueError on bad
            input; refusing on a full disk is a new failure mode

        The check itself is one line against psutil.disk_usage(...).free.

        TODO: implement as part of TELA-27653.
        """
        return _megabytes_to_bytes(self._retention_value("minFreeDiskSpace"))
