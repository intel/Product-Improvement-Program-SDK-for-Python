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

import hashlib
import json
import os
import re
import secrets
import time
import uuid
import zipfile
from collections import namedtuple

import zstandard

from iaspython._core import utils
from iaspython._core.logger import logger as log
from iaspython._core.store import set_mode

EVENTS_CONTENT_TYPE = "intel-ias-events-v1"
ATTACH_CONTENT_TYPE = "intel-ias-attachments-v1"
FILE_MANIFEST_NAME = "file_manifest.json.zst"
MANIFEST_SOURCE_TYPE = "File"

# Identifies the collector that produced the record, not the instrumented app.
SKR_SOURCE_NAME = "IasPython"

# The telemetry id every application using this SDK shares.
IAS_TELEMETRY_ID = "REDACTED"

# Points a development build at an unreleased policy.
IAS_TELEMETRY_ID_ENV = "IASPYTHON_POLICY_TELEMETRY_ID"

# Read size for hashing and copying staged content. Attachments can be crash
# dumps, so content is never held in memory whole.
CHUNK_SIZE = 1024 * 1024

# Record content staged on disk, ready to be streamed to the cloud.
#
# path:   the staged file. The caller owns it and has to delete it.
# size:   its size in bytes, for the record's content metadata
# digest: its sha256 hex digest, for the record's content metadata
StagedContent = namedtuple("StagedContent", ["path", "size", "digest"])

# One attachment resolved to a file on disk, with the story fields its manifest
# line is written from.
#
# guid:     names the file both in the store and in the ZIP
# path:     the stored file
# name:     the source filename, or the attachment name when there was no file
# size:     the size of the content handed over, before any compression
# encoding: the stored bytes' content encoding, "zlib" or "raw"
AttachmentFile = namedtuple("AttachmentFile", ["guid", "path", "name", "size", "encoding"])


# uuid.uuid7 arrived in 3.14 and this SDK supports 3.11 up, so on older
# interpreters the name is absent and _uuid7_fallback stands in. getattr, so
# importing this module does not depend on the version.
_stdlib_uuid7 = getattr(uuid, "uuid7", None)


def resolve_ias_telemetry_id():
    """Returns the telemetry id the policy is fetched under.

    Honors IAS_TELEMETRY_ID_ENV, a development setting that points a build at
    a policy which has not shipped yet. The override has to be a well-formed
    GUID, since it becomes a path segment of the policy URL.

    Read on every call rather than once at import, so a long-running process
    is not holding the value it started with.

    Returns:
        str: The override when it is usable, otherwise IAS_TELEMETRY_ID.
    """
    override = os.environ.get(IAS_TELEMETRY_ID_ENV, "").strip()
    if not override:
        return IAS_TELEMETRY_ID
    if not utils.is_valid_guid(override):
        log.error("{} is not a GUID, ignoring it".format(IAS_TELEMETRY_ID_ENV))
        return IAS_TELEMETRY_ID
    # Warning, not info: a release build that picked this up by accident is
    # fetching the wrong policy and has to say so in its own logs.
    log.warning(
        "the policy telemetry id is overridden by {}, this is a development setting".format(IAS_TELEMETRY_ID_ENV)
    )
    return override


def uuid7():
    """Returns a new UUID version 7, as a string.

    Version 7 leads with a millisecond timestamp, so ids sort by creation
    time. The SKR records API requires it.

    Prefers the standard library's generator, which also keeps a counter so
    two ids made in the same millisecond stay ordered; the fallback cannot.
    """
    if _stdlib_uuid7 is not None:
        return str(_stdlib_uuid7())
    return str(_uuid7_fallback())


def _uuid7_fallback():
    """Returns a UUID version 7 for Pythons whose uuid module has no uuid7().

    RFC 9562 section 5.7, most significant bit first:

        48 bits   unix_ts_ms   milliseconds since the epoch
         4 bits   ver          always 7
        12 bits   rand_a       random
         2 bits   var          always 0b10
        62 bits   rand_b       random

    The 74 random bits come from secrets.token_bytes, the same OS generator
    uuid4 and uuid7 draw on. Only the intra-millisecond ordering guarantee is
    missing.
    """
    ms = time.time_ns() // 1_000_000
    # 80 bits, 6 more than the 74 needed; the surplus is masked off below.
    rand = int.from_bytes(secrets.token_bytes(10), "big")
    # One term per row of the layout above, shifted to that row's bit
    # position, so the assembly can be checked against it line by line.
    return uuid.UUID(
        int=(ms << 80)  # unix_ts_ms, 48 bits
        | (0x7 << 76)  # ver
        | (((rand >> 62) & 0xFFF) << 64)  # rand_a, 12 bits
        | (0b10 << 62)  # var
        | (rand & 0x3FFF_FFFF_FFFF_FFFF)  # rand_b, 62 bits
    )


def _ndjson_line(row):
    """Encodes one row as a UTF-8 NDJSON line."""
    return (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")


def _compress_ndjson(lines):
    """Zstd-compresses already-encoded NDJSON lines.

    Each line is compressed as it is handed over; joining them into one string
    first would hold three copies of the content in memory. The zstd frame
    header needs the total size upfront, so the encoded line lengths are summed
    rather than the rows re-serialized.

    An empty list still yields a valid zstd frame, not b"".
    """
    compressor = zstandard.ZstdCompressor().compressobj(size=sum(len(line) for line in lines))
    chunks = [compressor.compress(line) for line in lines]
    chunks.append(compressor.flush())
    return b"".join(chunk for chunk in chunks if chunk)


def build_events_content(payload):
    """Builds zstd-compressed NDJSON events content for a payload.

    Attachment story entries ("t"=="atc") are moved out of stories into a
    separate attachments array in each row.

    Args:
        payload (dict): The stored payload to encode.

    Returns:
        tuple: (compressed_bytes, attachments). compressed_bytes is zstd UTF-8
        NDJSON, empty if there are no reports. attachments are the attachment
        story entries found, so the caller can build the ZIP and its manifest.
    """
    appid = payload["tid"]
    version = payload["version"]
    attachments = []
    lines = []

    for report in payload.get("reports", []):
        row = {
            "appid": appid,
            "uid": report.get("uid"),
            "version": version,
            "env": report.get("env"),
            "stories": [],
            "attachments": [],
        }

        for session_stories in report.get("stories", []):
            for entry in session_stories:
                if entry.get("t") == "atc":
                    g = entry.get("g", "")
                    # An attachment GUID becomes both a filename and a ZIP
                    # entry name, so it is held to the SDK's own GUID format
                    # rather than to a denylist. That rejects separators,
                    # trailing dots and spaces, Windows device names and
                    # control characters in one step.
                    if utils.is_valid_guid(g):
                        row["attachments"].append(entry)
                        attachments.append(entry)
                    # Attachments with unusable GUIDs are dropped.
                else:
                    row["stories"].append(entry)

        lines.append(_ndjson_line(row))

    if not lines:
        return b"", attachments

    return _compress_ndjson(lines), attachments


def build_manifest_bytes(files, appid):
    """Builds the zstd-compressed NDJSON package manifest.

    One line per packaged attachment. The package
    can reach the cloud before the events record it belongs to, so this is the
    only description of it the service can rely on.

    Args:
        files (list): The AttachmentFiles actually written into the ZIP.
        appid (str): The application id.

    Returns:
        bytes: The zstd-compressed manifest, one NDJSON line per attachment.
    """
    lines = [
        _ndjson_line(
            {
                "upload_file_name": f.guid,
                "orig_file_name": f.name,
                "file_collection_id": appid,
                "source_type": MANIFEST_SOURCE_TYPE,
                "orig_size_bytes": f.size,
                "compression_type": f.encoding,
            }
        )
        for f in files
    ]
    return _compress_ndjson(lines)


def build_zip_file(files, dest, appid):
    """Builds the attachments package and leaves it staged on disk.

    The package is a ZIP of the attachment files, each named after its GUID,
    plus the file_manifest.json.zst describing them.

    Nothing is held in memory whole -- not while the archive is built, hashed
    or uploaded -- because an attachment set can be crash-dump sized. The
    manifest is the exception, at six short fields per attachment.

    Args:
        files (list): The AttachmentFiles to package.
        dest (str): Where to build it, chosen by
            AttachmentStore.zip_staging_path. Inside the store rather than the
            system temp folder, because on Windows a file inherits the ACL of
            the folder it is created in and the mode below means nothing.
        appid (str): The application id, written to every manifest line.

    Returns:
        StagedContent: The archive. The caller owns the file and must delete
        it once the upload is done with it.

    Raises:
        OSError: If the archive could not be built. The staged file is
            removed first, so nothing is left behind.
    """  # noqa: DOC503
    # O_EXCL so a staged archive is never handed a file left at that name by
    # someone else. Same pattern as create_private.
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, utils.TEMP_FILE_MODE)
    os.close(fd)

    # The umask subtracts from what open asked for, and chmod is not filtered
    # that way. set_mode logs and carries on rather than raising: a filesystem
    # can take writes while refusing a chmod (CIFS does), and the umask can
    # only have made this stricter. Failing here would delete the archive and
    # lose every attachment on the record over a mode that is already safe.
    set_mode(dest, utils.TEMP_FILE_MODE)

    try:
        with zipfile.ZipFile(dest, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            packaged = []
            for f in files:
                try:
                    zf.write(f.path, arcname=f.guid)
                except FileNotFoundError as e:
                    # Retention can reap an attachment between the moment the
                    # record's file list was collected and now. A missing
                    # attachment never fails a record; its metadata still
                    # travels in the events content.
                    #
                    # Only a file that is genuinely gone. Any other I/O error
                    # is about a file that could still be read later, so it is
                    # left to fail the record and the payload is retried.
                    log.warning("skipping attachment {} while building the zip: {}".format(f.guid, e))
                    continue
                packaged.append(f)

            # Written from what landed rather than from what was asked for: the
            # dispatch service uploads one blob per line, so a line for a reaped
            # attachment would fail on every redelivery. Stored rather than
            # deflated, the bytes being zstd already.
            zf.writestr(FILE_MANIFEST_NAME, build_manifest_bytes(packaged, appid), compress_type=zipfile.ZIP_STORED)
        return StagedContent(dest, os.path.getsize(dest), sha256_file_hex(dest))
    except Exception:
        # The staged file has no owner yet, so it would leak.
        remove_staged_content(dest)
        raise


def remove_staged_content(path):
    """Deletes a staged content file, logging a failure rather than raising."""
    if not path:
        return
    try:
        os.remove(path)
    except OSError as e:
        log.error("failed to delete staged content file {}: {}".format(path, e))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file_hex(path):
    """Returns the sha256 hex digest of a file, read a chunk at a time."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_skr_record_body(sdk_version, ias_telemetry_id, did, record_uuid, events_meta, attach_meta):
    """Builds the JSON body for POST /records.

    Args:
        sdk_version (str): This SDK's version, reported as source.version.
        ias_telemetry_id (str): The IAS telemetry id.
        did (str): Device UUID.
        record_uuid (str): UUID for this record, also used in filenames.
        events_meta (dict): hash, size and filename of the ZSTD events blob.
        attach_meta (dict): The same for the ZIP blob, or None.

    Returns:
        dict: The request body for POST /records.
    """
    source = {
        "name": SKR_SOURCE_NAME,
        "type": "collector",
        "version": sdk_version,
    }

    contents = {
        EVENTS_CONTENT_TYPE: {
            "version": 1,
            "metadata": {
                "sources": [source],
                "contentType": "application/x-zstd",
                "contentEncoding": "zstd",
                "filename": events_meta["filename"],
                "hash": {"digest": events_meta["hash"], "type": "sha256"},
                "size": events_meta["size"],
            },
        }
    }

    if attach_meta is not None:
        contents[ATTACH_CONTENT_TYPE] = {
            "version": 1,
            "metadata": {
                "sources": [source],
                "contentType": "application/zip",
                "contentEncoding": "zip",
                "filename": attach_meta["filename"],
                "hash": {"digest": attach_meta["hash"], "type": "sha256"},
                "size": attach_meta["size"],
            },
        }

    return {
        "version": 1,
        "uuid": record_uuid,
        "nonce": str(uuid.uuid4()),
        "source": source,
        "system": {
            "purpose": "field",
            "id": {"uuid": did, "rawid": did, "source": "random"},
        },
        "tenancy": {"telemetryId": ias_telemetry_id},
        "terms": {"appManagedConsent": True},
        "contents": contents,
    }


def build_post_headers(useragent):
    """Returns the headers for the POST /records request."""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": useragent,
        "X-Request-Id": str(uuid.uuid4()),
        "X-Intel-Accepts-Blob-Urls": "azure?v=1.0,direct?v=1.0",
    }


def response_data(resp):
    """Returns the data section every SKR REST response wraps its payload in.

    Both POST /records and GET /policy are enveloped this way, so the policy
    document is at resp["data"] rather than the top level.

    Returns None rather than raising for anything misshapen, including a
    response that is not a JSON object -- a successful request with an empty
    body arrives as a string. Callers read None as "keep what we have and
    retry".
    """
    if not isinstance(resp, dict):
        return None
    data = resp.get("data")
    if not isinstance(data, dict):
        return None
    return data


# \Z rather than $ in all three: $ also matches before a trailing newline, so
# a value ending in the very LF being rejected would have passed.

# RFC 9110 field-name: a token.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")

# RFC 9110 field-value: visible ASCII, space and tab between the ends but not
# at them. Empty is valid; " x" is not, and requests refuses it outright.
_HEADER_VALUE_RE = re.compile(r"^(?:[\x21-\x7e](?:[\t\x20-\x7e]*[\x21-\x7e])?)?\Z")

# Apache's defaults: the whole "Name: value" line, and how many of them.
MAX_HEADER_LINE_LEN = 8190
_HEADER_SEPARATOR_LEN = len(": ")
MAX_REQUIRED_HEADERS = 100

# Lowered. Framing and hop-by-hop (RFC 9110 7.6.1), plus Host and Expect:
# the transport sets these from the request it is making, and a server-
# supplied one reaches the wire beside it. Two lengths on one request is a
# smuggling primitive.
FORBIDDEN_HEADERS = frozenset(
    [
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
        "host",
        "expect",
    ]
)

# RFC 9110 entity-tag: an optional weak marker, then etagc in quotes.
_ETAG_QUOTED_RE = re.compile(r'^(?:W/)?"[\x21\x23-\x7e]*"\Z')

# Servers emit an unquoted tag too.
_ETAG_UNQUOTED_RE = re.compile(r"^[\x21-\x7e]+\Z")

# Only meaningful delimited, so unquoted they are rejected: "*" is any
# representation and a comma makes If-None-Match a list, either of which can
# draw a 304 for a document the cache does not hold.
_ETAG_UNQUOTED_ILLEGAL_CHARS = '"*,'

MAX_ETAG_LEN = 256


def _is_entity_tag(etag):
    """True if etag names exactly one representation."""
    if _ETAG_QUOTED_RE.match(etag):
        return True
    return bool(_ETAG_UNQUOTED_RE.match(etag)) and not any(c in _ETAG_UNQUOTED_ILLEGAL_CHARS for c in etag)


def accepted_etag(etag):
    """Returns an entity-tag safe to echo back, or None.

    None means no revalidation, so the next fetch downloads the document
    rather than sending If-None-Match. Cheaper than the alternative: this
    value reaches a request header and is persisted, so a bad one would fail
    every flush until the cache file was removed.

    Args:
        etag (str): The ETag response header, or the value stamped into the
            cached document. Any value is accepted; neither source is trusted.

    Returns:
        str: The entity-tag, or None if it is not safe to echo back.
    """
    if not isinstance(etag, str) or not etag:
        return None
    if len(etag) > MAX_ETAG_LEN:
        log.error("ignoring an ETag longer than %d characters", MAX_ETAG_LEN)
        return None
    if not _is_entity_tag(etag):
        log.error("ignoring an ETag that does not name a single representation")
        return None
    return etag


def policy_request_headers(useragent, etag=None):
    """Returns the headers for the GET /policy request.

    Accept-Encoding: zstd is deliberately omitted. requests only decodes zstd
    when urllib3 was installed with that extra, so advertising it could turn a
    working fetch into an unreadable body. Both clients advertise what they
    can actually decode.
    """
    headers = {
        "User-Agent": useragent,
        "X-Request-Id": str(uuid.uuid4()),
    }
    if etag:
        # Revalidation: the service answers 304 rather than resending a
        # document already cached.
        headers["If-None-Match"] = etag
    return headers


def policy_useragent(agent, agent_version):
    """Returns the agent/version a policy request identifies itself with.

    For example "IasPython/1.0.0.0". The uploader appends the platform; see
    SkrUploaderBase.
    """
    return "{}/{}".format(agent, agent_version)


def _response_content_entry(resp, content_type):
    """Returns data.contents[content_type] of a POST /records response.

    None if any step of the path is missing or misshapen, including a
    response that is not a JSON object at all.
    """
    data = response_data(resp)
    if data is None:
        return None
    contents = data.get("contents")
    if not isinstance(contents, dict):
        return None
    entry = contents.get(content_type)
    if not isinstance(entry, dict):
        return None
    return entry


def _accepted_required_headers(required_headers, content_type):
    """Returns the server-supplied upload headers, or None if any is unusable.

    These come out of a response body and are written onto the wire. Not left
    to the transports, which refuse a bad one differently: aiohttp raises a
    bare ValueError or TypeError, neither a ClientError, so both escape
    _request's handler into the calling application's flush.

    All or nothing. Dropping just the bad header would send the PUT without
    something the target asked for, which a presigned target refuses anyway.
    """
    if required_headers is None:
        return {}
    if not isinstance(required_headers, dict):
        # The type only, for the reason the value is withheld below.
        log.error(
            "SKR content %s was accepted with requiredHeaders that are not an object: %s",
            content_type,
            type(required_headers).__name__,
        )
        return None
    if len(required_headers) > MAX_REQUIRED_HEADERS:
        log.error(
            "SKR content %s was accepted with %d requiredHeaders, over the %d allowed",
            content_type,
            len(required_headers),
            MAX_REQUIRED_HEADERS,
        )
        return None
    for key, value in required_headers.items():
        if not isinstance(key, str) or not _HEADER_NAME_RE.match(key):
            # Truncated: a name has no length limit until the check below.
            log.error("SKR content %s was accepted with an unusable header name: %.40r", content_type, key)
            return None
        if key.lower() in FORBIDDEN_HEADERS:
            # Whole: it matched the set, so it is one of those.
            log.error("SKR content %s was accepted with header %s, which the transport owns", content_type, key)
            return None
        if not isinstance(value, str) or not _HEADER_VALUE_RE.match(value):
            # The name only, truncated: a required header can be a credential
            log.error("SKR content %s was accepted with an unusable value for header %.40s", content_type, key)
            return None
        if len(key) + _HEADER_SEPARATOR_LEN + len(value) > MAX_HEADER_LINE_LEN:
            log.error(
                "SKR content %s was accepted with header %.40s... over %d characters",
                content_type,
                key,
                MAX_HEADER_LINE_LEN,
            )
            return None
    return dict(required_headers)


def _merge_headers(headers, overrides):
    """Applies overrides to headers, matching names case-insensitively.

    dict.update would leave a server's "content-type" beside the default
    "Content-Type", and aiohttp builds a multidict from this, so both would go
    on the wire and a presigned target would reject the signature.
    """
    # Indexed rather than scanned per override: a response inside the body cap
    # can carry tens of thousands of headers, and rescanning would be quadratic.
    by_lower = {name.lower(): name for name in headers}
    for name, value in overrides.items():
        lowered = name.lower()
        existing = by_lower.get(lowered)
        if existing is not None and existing != name:
            del headers[existing]
        headers[name] = value
        by_lower[lowered] = name
    return headers


def resolve_upload_target(resp, content_type, useragent):
    """Extracts the presigned PUT url and headers for one content type.

    Every step reads the response defensively rather than indexing into it,
    since a POST that succeeds with an empty body reaches here as a string.
    Callers read None as "save the payload and retry later".

    This url is the least trusted of the SDK's three destinations: it is
    simply whatever came back in a response body, so its scheme is checked
    here too. That the POST was over TLS says who answered, not where they
    are pointing.

    Args:
        resp (dict): The parsed body of the POST /records response.
        content_type (str): The content type to find an upload target for.
        useragent (str): The user agent to send with the PUT.

    Returns:
        tuple|None: (url, headers), or None if there is no accepted upload
        target for content_type, or it is not https.
    """
    # The commented-out calls below log the whole response body, which carries
    # the presigned urls whose query strings authorize a write. Uncomment them
    # while debugging; they stay commented in anything that ships.
    entry = _response_content_entry(resp, content_type)
    if entry is None:
        log.error("SKR content %s was not accepted: missing entry in response contents", content_type)
        # log.error("SKR response=%s", resp)
        return None
    if entry.get("status") != "accepted":
        log.error("SKR content %s was not accepted: status=%r", content_type, entry.get("status"))
        # log.error("SKR response=%s", resp)
        return None

    url = entry.get("url")
    if not url or not isinstance(url, str):
        log.error("SKR content %s was accepted without a usable upload url", content_type)
        # log.error("SKR response=%s", resp)
        return None
    if not utils.is_tls_url(url):
        # Only the origin: the signature authorizing this write is in the
        # query string. The record is kept and retried.
        log.error("SKR content %s was given an upload url that is not https: %s", content_type, utils.url_origin(url))
        return None
    upload_type = entry.get("type", "direct")

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/octet-stream",
        "User-Agent": useragent,
    }

    # Upload-type defaults, applied before requiredHeaders so the server can
    # override them.
    if upload_type == "azure":
        # Azure targets go straight to blob storage.
        headers["x-ms-blob-type"] = "blockblob"
    elif upload_type == "direct":
        # Direct targets go back through the SKR cloud API.
        headers["X-Request-Id"] = str(uuid.uuid4())

    # Server-supplied headers win, but every name and value is checked first.
    required_headers = _accepted_required_headers(entry.get("requiredHeaders"), content_type)
    if required_headers is None:
        return None
    _merge_headers(headers, required_headers)

    return url, headers
