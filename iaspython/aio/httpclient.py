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

import aiohttp

from iaspython._core import tlsconfig, utils
from iaspython._core.logger import logger as log

# Per-socket rather than total. A total deadline would abort a large attachment
# upload that is progressing normally, and raises a bare asyncio.TimeoutError,
# which is not an aiohttp.ClientError and would escape the handler below.
# sock_connect and sock_read raise ClientError subclasses. See _core/utils.py
# for the values.
HTTP_TIMEOUT = aiohttp.ClientTimeout(
    sock_connect=utils.HTTP_CONNECT_TIMEOUT_SECONDS,
    sock_read=utils.HTTP_READ_TIMEOUT_SECONDS,
)


class HttpClient:
    def __init__(self, proxy=None):
        self.proxy = proxy
        # Private: aiohttp has no per-request equivalent of requests' verify, so
        # this context is the whole of the enforcement. Shared with the sync
        # surface so the two cannot drift.
        self._ssl_context = tlsconfig.build_ssl_context()
        # trust_env, because aiohttp ignores HTTP_PROXY/HTTPS_PROXY/NO_PROXY
        # unless it is set. An explicit proxy is passed per request and wins.
        self._client = aiohttp.ClientSession(trust_env=True, timeout=HTTP_TIMEOUT)

    async def get(self, url, headers=None):
        """Issues a GET request.

        Args:
            url (str): The destination.
            headers (dict, optional): Request headers.

        Returns:
            tuple: (success, doc, response_headers, status). The status is
            returned explicitly because a 200 with an empty or unparseable body
            also yields no document, and must not be mistaken for a 304.
        """
        return await self._request("GET", url, headers=headers)

    async def put(self, url, content, headers):
        success, resp, headers, _status = await self._request("PUT", url, content, headers)
        return success, resp, headers

    async def post(self, url, content, headers):
        success, resp, headers, _status = await self._request("POST", url, content, headers)
        return success, resp, headers

    async def _request(self, method, url, content=None, headers=None):
        if not utils.check_request(method, url, content, headers):
            return False, None, None, None
        try:
            async with self._client.request(
                method,
                url,
                data=content,
                headers=headers,
                proxy=self.proxy,
                ssl=self._ssl_context,
                # never follow a 3xx: an http:// Location would drop TLS
                allow_redirects=False,
            ) as resp:
                return await self._response(method, resp)
        except aiohttp.ClientError as e:
            tlsconfig.log_request_failure(method, url, e)
            return False, None, None, None

    async def _body(self, resp):
        """Returns the response body as text, or None if it is unusable.

        A chunk at a time, not resp.text(), which allocates the whole body
        first. The stream has any Content-Encoding already undone, which is
        where the amplification is.
        """
        buf = utils.BodyBuffer()
        try:
            async for chunk in resp.content.iter_chunked(utils.RESPONSE_CHUNK_SIZE):
                if not buf.add(chunk):
                    return None
        except aiohttp.ClientPayloadError:
            log.error("the response body could not be decoded, not reading it")
            return None
        return buf.text()

    async def _response(self, method, resp):
        log.debug("--- Received HTTP response ---")
        status = resp.status
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
            data = await self._body(resp)
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
            log.error(
                "http response text: {}".format(utils.strip_url_secrets(utils.body_for_log(await self._body(resp))))
            )
            return False, None, None, status

    async def close(self):
        if not self._client.closed:
            await self._client.close()
