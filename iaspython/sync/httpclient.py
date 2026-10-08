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

import json

import requests
from requests.adapters import HTTPAdapter

from iaspython._core import tlsconfig, utils
from iaspython._core.logger import logger as log

# The (connect, read) pair requests expects. See _core/utils.py for the values.
HTTP_TIMEOUT_SECONDS = (utils.HTTP_CONNECT_TIMEOUT_SECONDS, utils.HTTP_READ_TIMEOUT_SECONDS)


class TlsAdapter(HTTPAdapter):
    """Transport adapter that applies the SDK's SSLContext.

    requests exposes no parameter for an SSLContext -- `verify` only chooses a
    CA bundle -- so the pool manager is the only place to inject one.
    """

    def __init__(self, *args, **kwargs):
        # Set before super(), which calls init_poolmanager.
        self._ssl_context = tlsconfig.build_ssl_context()
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, *args, **kwargs):
        # A proxied connection gets its own pool manager, built from urllib3's
        # defaults unless the context is passed here too.
        kwargs["ssl_context"] = self._ssl_context
        if proxy.lower().startswith("https://"):
            # Reaching an https proxy is a second TLS connection; urllib3 takes
            # its context from proxy_ssl_context. SOCKSProxyManager rejects it.
            kwargs["proxy_ssl_context"] = self._ssl_context
        return super().proxy_manager_for(proxy, *args, **kwargs)


class HttpClient:
    def __init__(self, proxy=None):
        # None rather than {"http": None, "https": None}: an explicit dict blocks
        # requests' own resolution of HTTP_PROXY/HTTPS_PROXY/NO_PROXY and the
        # Windows system proxy settings.
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self._session = requests.Session()
        self._session.verify = True
        self._session.mount("https://", TlsAdapter())

    def get(self, url, headers=None):
        """Issues a GET request.

        Args:
            url (str): The destination.
            headers (dict, optional): Request headers.

        Returns:
            tuple: (success, doc, response_headers, status). The status is
            returned explicitly because a 200 with an empty or unparseable body
            also yields no document, and must not be mistaken for a 304.
        """
        return self._request("GET", url, headers=headers)

    def put(self, url, content, headers):
        success, resp, headers, _status = self._request("PUT", url, content, headers)
        return success, resp, headers

    def post(self, url, content, headers):
        success, resp, headers, _status = self._request("POST", url, content, headers)
        return success, resp, headers

    def _request(self, method, url, content=None, headers=None):
        if not utils.check_request(method, url, content, headers):
            return False, None, None, None
        try:
            with self._session.request(
                method,
                url,
                data=content,
                headers=headers,
                proxies=self.proxies,
                timeout=HTTP_TIMEOUT_SECONDS,
                # never follow a 3xx: an http:// Location would drop TLS
                allow_redirects=False,
                # requests prefers this over session.verify
                verify=True,
                # so _body can stop reading at the cap
                stream=True,
            ) as resp:
                return self._response(method, resp)
        except requests.exceptions.RequestException as e:
            # Not traceback.format_exc(): a formatted traceback embeds the
            # exception message, presigned query string and all.
            tlsconfig.log_request_failure(method, url, e)
            return False, None, None, None

    def _body(self, resp):
        """Returns the response body as text, or None if it is unusable.

        A chunk at a time, not resp.text, which allocates the whole body
        first. iter_content has any Content-Encoding already undone, which is
        where the amplification is.
        """
        buf = utils.BodyBuffer()
        try:
            for chunk in resp.iter_content(utils.RESPONSE_CHUNK_SIZE):
                if not buf.add(chunk):
                    return None
        except requests.exceptions.ContentDecodingError:
            log.error("the response body could not be decoded, not reading it")
            return None
        return buf.text()

    def _response(self, method, resp):
        log.debug("--- Received HTTP response ---")
        status = resp.status_code
        if status == utils.STATUS_NOT_MODIFIED and method == "GET":
            # GET only. On a PUT a 304 would report content that never arrived
            # as uploaded, and the uploader deletes the payload on that word.
            # Headers are still returned, for the ETag.
            log.debug("status code: {} (not modified)".format(status))
            return True, None, resp.headers, status
        if status in (utils.STATUS_OK, utils.STATUS_CREATED):
            log.debug("status code: {}".format(status))
            # Returned for GET too: the policy fetch reads the ETag so the next
            # request can revalidate.
            headers = resp.headers
            log.debug("headers=\n{}".format(headers))
            data = self._body(resp)
            if data is None:
                if method == "PUT":
                    # No caller reads a PUT body, so an unusable one is not a
                    # failed upload: reporting failure would re-send content
                    # the target already accepted, on every flush.
                    return True, None, headers, status
                # Nothing was learned about the document, so callers retry.
                return False, None, None, status
            try:
                data = json.loads(data)
                log.debug("content=\n{}".format(json.dumps(data, indent=2)))
            except:
                log.debug("content=\n{}".format(data))
            return True, data, headers, status
        else:
            log.error("http response status code: {}".format(status))
            log.error("http response text: {}".format(utils.strip_url_secrets(utils.body_for_log(self._body(resp)))))
            return False, None, None, status

    def close(self):
        """Releases the sockets held by the session's connection pool."""
        self._session.close()
