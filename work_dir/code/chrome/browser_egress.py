"""Browser-TLS egress client.

httpx/OpenSSL produces a non-browser TLS + HTTP/2 fingerprint (HTTP/1.1,
Python JA3, python UA) that Binance's secure-link «different networks» check
now flags, even when the egress IP matches. curl_cffi reproduces the exact
browser handshake (JA3/JA4 + HTTP/2 settings) for the chosen impersonate
target, so the egress is indistinguishable from a real browser.
"""

from __future__ import annotations

import asyncio
import logging

from curl_cffi import requests as cffi_requests
from curl_cffi.requests import BrowserType

logger = logging.getLogger(__name__)


class BrowserEgressClient:
    """Async egress client with a real browser TLS/HTTP2 fingerprint.

    Mimics the interface used by the proxy (``request_with_retry`` + async
    context manager) so it can be swapped in for the httpx-based client.
    """

    def __init__(
        self,
        proxy: str | None = None,
        impersonate: str = "chrome131_android",
        user_agent: str | None = None,
        extra_headers: dict | None = None,
        attempts: int = 3,
    ):
        self._proxy = proxy
        self._impersonate = impersonate
        self._user_agent = user_agent
        self._extra_headers = dict(extra_headers or {})
        self._attempts = max(1, attempts)
        self._session: cffi_requests.AsyncSession | None = None

    async def __aenter__(self) -> "BrowserEgressClient":
        self._session = cffi_requests.AsyncSession(impersonate=self._impersonate)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None

    @property
    def proxy(self) -> str | None:
        return self._proxy

    def _build_headers(self, headers: dict | None) -> dict:
        # The impersonate target already sets a matching browser UA and
        # sec-ch-ua. Override the UA only if an explicit one is supplied
        # (to match the creation browser exactly).
        hdrs = dict(headers or {})
        if self._user_agent:
            hdrs["User-Agent"] = self._user_agent
        hdrs.update(self._extra_headers)
        return hdrs

    def _timeout_value(self, timeout) -> float | None:
        if timeout is None:
            return None
        if hasattr(timeout, "read"):  # httpx.Timeout
            return float(timeout.read or 30.0)
        if isinstance(timeout, (int, float)):
            return float(timeout)
        return 30.0

    async def request_with_retry(
        self,
        method: str,
        url: str,
        follow_redirects: bool = False,
        **request_kwargs,
    ):
        if self._session is None:
            raise RuntimeError("BrowserEgressClient used outside of async context")

        headers = self._build_headers(request_kwargs.pop("headers", None))
        content = request_kwargs.get("content")
        cookies = dict(request_kwargs.get("cookies") or {})
        timeout = self._timeout_value(request_kwargs.get("timeout"))
        request_kwargs.pop("cookies", None)
        request_kwargs.pop("timeout", None)
        # drop anything curl_cffi.request doesn't accept
        request_kwargs = {
            k: v for k, v in request_kwargs.items()
            if k in {"params", "data", "json", "files", "auth", "verify",
                     "referer", "accept_encoding", "http_version", "interface"}
        }

        req_kwargs = dict(
            method=method,
            url=url,
            headers=headers,
            content=content,
            cookies=cookies,
            allow_redirects=follow_redirects,
        )
        if timeout is not None:
            req_kwargs["timeout"] = timeout
        if self._proxy:
            req_kwargs["proxies"] = {"http": self._proxy, "https": self._proxy}
        req_kwargs.update(request_kwargs)

        last_exc: Exception | None = None
        for attempt in range(1, self._attempts + 1):
            try:
                response = await self._session.request(**req_kwargs)
                # Retry transient server errors / rate limits.
                if response.status_code in (429, 500, 502, 503, 504) and attempt < self._attempts:
                    await asyncio.sleep(min(0.5 * (2 ** (attempt - 1)), 5.0))
                    continue
                return response
            except Exception as exc:  # noqa: BLE001 - retry any transport error
                last_exc = exc
                if attempt >= self._attempts:
                    break
                await asyncio.sleep(min(0.5 * (2 ** (attempt - 1)), 5.0))
        if last_exc is not None:
            raise last_exc
        # unreachable
        raise RuntimeError("request_with_retry: no response")
