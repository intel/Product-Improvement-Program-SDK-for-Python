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

import gzip
import json
import logging
import os
import re
import shutil
from urllib.parse import urlparse

from iaspython._core.logger import logger as log

# The only URL scheme telemetry may be uploaded over. Checked wherever a
# destination enters the SDK, since none of the transport's other guarantees
# are reached if the connection is not TLS to begin with.
UPLOAD_SCHEME = "https"

# Owner-only permissions for a file the SDK puts in the shared temp folder.
# See STORE_FILE_MODE in _core/store.py.
TEMP_FILE_MODE = 0o600

# How much of a file is held in memory at once while it is being compressed.
COPY_CHUNK_SIZE = 1024 * 1024


def _remove_partial(path):
    """Deletes a half-written file, logging a failure rather than raising.

    The caller is already returning a failure and has no path to hand back, so
    nothing else is left to clean the file up.
    """
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as e:
        log.error("failed to delete partial file '{}': {}".format(path, e))


def join_url(base, path):
    """Joins a base URL and a path with exactly one '/' between them."""
    return base.rstrip("/") + "/" + path.lstrip("/")


def parse_url(url):
    """Parses a URL, returning None for anything urlparse or .port rejects.

    .port is read here because it parses lazily: urlparse accepts
    "https://host:notaport" and only raises when the port is taken.

    Args:
        url (str): The value to parse. Any value is accepted.

    Returns:
        ParseResult|None: The parsed URL, or None if it is unusable.
    """
    if not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url)
        parsed.port
    except ValueError:
        return None
    return parsed


def url_host(parsed):
    """Returns host[:port] from a parsed URL, with any userinfo dropped.

    netloc carries "user:password@"; hostname drops it, and also drops the
    brackets an IPv6 literal needs back.

    Args:
        parsed (ParseResult): A URL parsed by parse_url() or urlparse().

    Returns:
        str|None: None if the URL names no host at all, e.g. "https://@/".
    """
    host = parsed.hostname
    if host is None:
        return None
    if ":" in host:
        host = "[{}]".format(host)
    return host if parsed.port is None else "{}:{}".format(host, parsed.port)


def is_tls_url(url):
    """Reports whether a URL names an https destination the SDK may upload to.

    Accepts any value, not just strings: two of the three callers check a URL
    that came from outside the SDK, where nothing guarantees a string.

    Parsed rather than prefix-matched, because that is what requests and
    aiohttp do with it: "https:/host/x" has a scheme and no host, and "HTTPS://"
    is the same scheme in a different case.

    The host comes from hostname, not netloc: netloc is non-empty for
    "https://@/" and "https://:443/", which name no host.

    Args:
        url (str): The value to check.

    Returns:
        bool: True if this is an https URL with a host.
    """
    parsed = parse_url(url)
    if parsed is None:
        return False
    return parsed.scheme.casefold() == UPLOAD_SCHEME and bool(parsed.hostname)


def url_origin(url):
    """Returns the scheme and host alone, for naming a URL in a log safely.

    A presigned upload url carries its authorizing signature in the query
    string, so the full url is a credential. So is any userinfo.

    Args:
        url (str): The URL to reduce. Any value is accepted.

    Returns:
        str: "scheme://host", or a placeholder if the URL cannot supply one.
    """
    if not isinstance(url, str):
        return "<not a url>"
    parsed = parse_url(url)
    if parsed is None:
        return "<unparseable url>"
    if not parsed.scheme or not parsed.hostname:
        return "<no scheme or host>"
    return "{}://{}".format(parsed.scheme, url_host(parsed))


# Anything from a "?" up to the next whitespace. Deliberately blunt: this runs
# over text the SDK did not compose, where the url is embedded mid-sentence and
# urlparse is no help. A quote does not end the match -- it is a legal query
# character, and stopping there would leave whatever followed it.
_QUERY_STRING_RE = re.compile(r"\?\S+")

# "user:password@" between "://" and the host. Excluding "/" keeps it from
# reaching past the authority into a path or a bare email address.
_USERINFO_RE = re.compile(r"(?<=://)[^/\s@]*@")


def strip_url_secrets(text):
    """Returns text with the credential parts of any url redacted.

    Two of them: the query string, which carries a presigned signature, and
    the userinfo, which carries a proxy or endpoint password.

    For text the SDK is only passing along, such as an exception message with a
    url interpolated into it. Use url_origin for a url the SDK itself holds.
    """
    return _USERINFO_RE.sub("<redacted>@", _QUERY_STRING_RE.sub("?<redacted>", text))


def content_length(content):
    """Measures a request body for logging, whether it is bytes or a stream.

    Never raises: a body about to be uploaded must not be lost to an exception
    thrown while describing it.

    Args:
        content (bytes or object): The request body, or a stream with a
            readable length.

    Returns:
        int|str: The length, or "unknown" if it cannot be measured.
    """
    try:
        return len(content)
    except TypeError:
        # A stream. Ask the file descriptor instead.
        pass
    try:
        return os.fstat(content.fileno()).st_size
    except (AttributeError, ValueError, OSError):
        # No fileno, a closed file, or one fstat cannot measure.
        # io.UnsupportedOperation is both an OSError and a ValueError.
        return "unknown"


def is_valid_guid(guid):
    """Reports whether a value is a GUID in the format the SDK issues.

    Accepts any value, not just strings. Callers ask about GUIDs they did not
    create -- handed in by an application, or read back out of stored JSON --
    and re.match would raise TypeError on a number or a list, turning "drop this
    attachment" into a failure that blocks the whole payload.
    """
    if not isinstance(guid, str):
        return False
    regex = re.compile("^([0-9a-f]{8}[-][0-9a-f]{4}[-][0-9a-f]{4}[-][0-9a-f]{4}[-][0-9a-f]{12})$")
    match = regex.match(guid)
    return bool(match)


def compress_string(content):
    return gzip.compress(bytes(content, "utf-8"))


def compress_bytes(content):
    return gzip.compress(content)


def compress_file(file_to_compress, file_compressed):
    """Gzips a file to a path the caller names.

    AttachmentStore.staging_path chooses that path, inside the store, so the
    compressed copy inherits the store's permissions rather than the system
    temp folder's.

    Args:
        file_to_compress (str): The file to read.
        file_compressed (str): Where to write the gzip. Must not already exist,
            and its folder must.

    Returns:
        str|None: file_compressed, or None if the gzip could not be produced.
    """
    if not os.path.exists(file_to_compress):
        log.error("file not found: '{}'".format(file_to_compress))
        return None

    path, extension = os.path.splitext(file_to_compress)

    if extension == ".gz" or extension == ".zip":
        # .format, not logging's %-style args: the template uses {}, so passing
        # the path as an argument makes the logger raise while formatting.
        log.error("filename appears already compressed: {}".format(file_to_compress))
        return None

    try:
        # os.open with an explicit mode, because gzip.open would create the file
        # at the machine's default permissions. O_EXCL because an existing name
        # belongs to an earlier attach that died part-way through; the retention
        # sweep reaps it by age.
        fd = os.open(file_compressed, os.O_CREAT | os.O_EXCL | os.O_WRONLY, TEMP_FILE_MODE)
    except OSError as e:
        log.error("failed to create compressed file '{}': {}".format(file_compressed, e))
        return None

    # The umask subtracts from the mode os.open asks for, but not from chmod.
    # Writing here works regardless, since the descriptor is already open, but
    # place() reads the file back when it has to copy rather than rename.
    # Through the descriptor, so it cannot land on another file.
    if hasattr(os, "fchmod"):
        try:
            os.fchmod(fd, TEMP_FILE_MODE)
        except OSError as e:
            # Not fatal: the umask can only have made this stricter.
            log.error("could not set mode on '{}': {}".format(file_compressed, e))

    try:
        # os.fdopen, because GzipFile needs a file object and gzip.open would
        # take only a path -- losing the permissions set above, and writing the
        # source filename into the gzip header in plain text. Here .name is the
        # integer descriptor, so no name is recorded.
        with os.fdopen(fd, "wb") as raw:
            with open(file_to_compress, "rb") as f_in, gzip.GzipFile(fileobj=raw, mode="wb") as f_out:
                # copyfileobj, not writelines: writelines splits on newlines, and
                # a binary file may contain none, loading the whole file into
                # memory as a single "line".
                shutil.copyfileobj(f_in, f_out, COPY_CHUNK_SIZE)
    except OSError as e:
        # The file exists by now, so a partial write leaves a truncated gzip of
        # attachment content behind and the caller never learns its path.
        log.error("failed to write compressed file '{}': {}".format(file_compressed, e))
        _remove_partial(file_compressed)
        return None

    if not os.path.exists(file_compressed):
        log.error("failed to create compressed file: '{}'".format(file_compressed))
        return None

    return file_compressed


# The HTTP status codes the clients act on explicitly.
STATUS_OK = 200
STATUS_CREATED = 201
# Conditional GET matched by If-None-Match. Success, with an empty body.
STATUS_NOT_MODIFIED = 304

# How long a request waits, in seconds. Defined here so the sync and async
# surfaces cannot drift apart; each spells it the way its own library wants.
#
# Neither is optional: requests applies no timeout at all, so a service that
# accepts the connection and then goes silent would hold the calling thread in
# flush() forever.
#
# The read half is per socket read, not a deadline for the whole exchange, so a
# large attachment upload keeps resetting the clock while bytes are moving.
#
# Thirty seconds either side states the existing behavior. Deliberately not
# configurable, which would make it public API for a value nothing has asked to
# change.
HTTP_CONNECT_TIMEOUT_SECONDS = 30
HTTP_READ_TIMEOUT_SECONDS = 30

# How much of a request body reaches a debug log line.
LOG_BODY_MAX_BYTES = 1024

# The largest response body the SDK will read, and how much is taken at a
# time. A policy document and a records response are both a few kilobytes.
#
# Counted off the decoded stream rather than from Content-Length, which
# reports the size on the wire: both clients advertise gzip and decode before
# anything can measure the result, so a 200 KB body becomes a 200 MB string.
MAX_RESPONSE_BYTES = 1024 * 1024
RESPONSE_CHUNK_SIZE = 64 * 1024

# Every body the SDK reads is JSON, which RFC 8259 requires to be UTF-8.
# Stated, because requests otherwise guesses at the charset -- falling back to
# ISO-8859-1 or chardet -- and the two surfaces could then disagree.
RESPONSE_ENCODING = "utf-8"


def body_for_log(content):
    """Renders a request body for a debug line. Never raises.

    Bytes are decoded leniently. A stream is described rather than read, since
    consuming it would leave nothing for the uploader to send.
    """
    if content is None:
        return "<none>"

    if isinstance(content, str):
        shown, total, unit = content[:LOG_BODY_MAX_BYTES], len(content), "characters"
    elif isinstance(content, (bytes, bytearray, memoryview)):
        # Sliced before copying: bytes(content) on a bytearray or memoryview
        # materializes the whole body just to show the front of it.
        shown = bytes(content[:LOG_BODY_MAX_BYTES]).decode("utf-8", "replace")
        total, unit = len(content), "bytes"
    else:
        return "<{}, not read for logging>".format(type(content).__name__)

    if total > LOG_BODY_MAX_BYTES:
        return "{}... ({} of {} {})".format(shown, LOG_BODY_MAX_BYTES, total, unit)
    return shown


def check_request(method, url, content, headers):
    """Logs an outgoing request and validates its method and destination.

    Shared by both transports: neither step awaits.

    Args:
        method (str): The HTTP method.
        url (str): The destination.
        content (bytes or object): The request body, logged by length only.
        headers (dict): The request headers.

    Returns:
        bool: True if the request should proceed. False if it was refused and
        already logged; the caller returns (False, None, None, None).
    """
    if log.isEnabledFor(logging.DEBUG):
        log.debug("--- Send HTTP {} request ---".format(method))
        log.debug("url={}".format(url if method == "GET" else strip_url_secrets(url)))
        if method != "GET":
            log.debug("headers=\n{}".format(json.dumps(headers, indent=2)))
            log.debug("length={}".format(content_length(content)))
            if headers.get("Content-Type") == "application/json" and "Content-Encoding" not in headers:
                log.debug("content=\n{}".format(body_for_log(content)))
    if method not in ("GET", "PUT", "POST"):
        return False
    if not is_tls_url(url):
        # The last gate before the socket. Every caller checks its own
        # destination first; this one holds for anything that reaches the
        # transport by another route. The proxy is not a destination and
        # is not checked here.
        log.error("refusing a {} to a destination that is not https: {}".format(method, url_origin(url)))
        return False
    return True


class BodyBuffer:
    """Accumulates a response body a chunk at a time, capped at MAX_RESPONSE_BYTES.

    One buffer, not a list of chunks: the server picks the sizes, and
    one-byte chunks cost 89x what they hold.
    """

    def __init__(self):
        self._body = bytearray()

    def add(self, chunk):
        """Returns False, without storing the chunk, once the cap is exceeded."""
        if len(self._body) + len(chunk) > MAX_RESPONSE_BYTES:
            log.error("the response body is over {} bytes, not reading it".format(MAX_RESPONSE_BYTES))
            return False
        self._body.extend(chunk)
        return True

    def text(self):
        """Returns the buffered body as text, or None if it is not valid RESPONSE_ENCODING."""
        try:
            # Strict, not "replace": a substituted U+FFFD still parses as JSON,
            # so the SDK would act on a value no server sent.
            return self._body.decode(RESPONSE_ENCODING)
        except UnicodeDecodeError:
            log.error("the response body is not valid {}, not reading it".format(RESPONSE_ENCODING))
            return None
