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

"""TLS policy for both the sync and async surfaces.

The two surfaces use different HTTP libraries. Building the SSLContext here
keeps their settings identical and independent of library defaults.
"""

import ssl

from iaspython._core import utils
from iaspython._core.logger import logger as log

# Lowest version negotiated. The maximum is left unpinned so TLS 1.3 is offered
# and preferred; 1.2 remains the floor because SKR hands out presigned urls on
# third-party storage the SDK does not control.
TLS_MINIMUM_VERSION = ssl.TLSVersion.TLSv1_2

# Marker logged on every TLS failure, so logs can be searched for it.
TLS_FAILURE_MARKER = "TLS failure"


def build_ssl_context():
    """Builds the SSLContext both surfaces negotiate with.

    Returns:
        ssl.SSLContext: A new context per call, since a context accumulates
        loaded certificates and session state.
    """
    # create_default_context() loads the platform certificate store; a bare
    # SSLContext would trust no issuer at all.
    context = ssl.create_default_context()

    # verify_mode first: check_hostname cannot be set while verification is off.
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    context.minimum_version = TLS_MINIMUM_VERSION
    context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    # The SDK holds short connections and presents no client certificate, so it
    # has no use for renegotiation. Unsafe renegotiation is already refused by
    # OpenSSL; this turns off the RFC 5746 form too.
    context.options |= ssl.OP_NO_RENEGOTIATION

    # CRIME. Already off in the stock context; set again so the guarantee does
    # not depend on the build.
    context.options |= ssl.OP_NO_COMPRESSION

    return context


def is_tls_error(exc):
    """Reports whether an exception originated in the TLS layer.

    Args:
        exc (BaseException): The exception to inspect.

    Returns:
        bool: True if an ssl.SSLError appears anywhere in the cause chain.
    """
    return any(isinstance(e, ssl.SSLError) for e in _walk(exc))


def _walk(exc):
    """Returns the exception cause chain, outermost first.

    Visited ids are tracked because a __context__ chain can contain a cycle.
    """
    chain, seen, current = [], set(), exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def log_request_failure(method, url, exc):
    """Logs a failed request, distinguishing TLS failures from network failures.

    Query strings are stripped from both the url and the exception message: a
    PUT target is a presigned url, and requests embeds the full url in its
    exception text.

    Args:
        method (str): HTTP method of the failed request.
        url (str): Request url. Only its origin is logged.
        exc (BaseException): The exception raised by the transport.
    """
    chain = _walk(exc)
    # The innermost cause says what went wrong; the outer wrapper only says that
    # something did.
    detail = utils.strip_url_secrets(str(chain[-1])) if chain else str(exc)
    types = " <- ".join(type(e).__name__ for e in chain)

    if is_tls_error(exc):
        log.error(
            "%s: %s %s could not establish a verified TLS session: %s (%s)",
            TLS_FAILURE_MARKER,
            method,
            utils.url_origin(url),
            detail,
            types,
        )
    else:
        log.error(
            "%s %s failed in transport: %s (%s)",
            method,
            utils.url_origin(url),
            detail,
            types,
        )
