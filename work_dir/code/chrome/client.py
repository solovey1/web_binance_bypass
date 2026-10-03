import asyncio
from typing import TypedDict, Literal
from http.cookiejar import Cookie
import warnings
import re

from better_proxy import Proxy
from httpx._utils import URLPattern
import httpx

from .retry_options import RetryOptionsBase, ExponentialRetry


class CookieDict(TypedDict):
    name: str
    value: str
    domain: str
    path: str
    expires: int
    secure: bool
    session: bool
    httpOnly: bool
    sameSite: Literal["unspecified", "no_restriction", "lax", "strict", "none"]


USER_AGENTS = {
    "macOS": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
             "AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/{chrome_version}.0.0.0 Safari/537.36",
    "Windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/{chrome_version}.0.0.0 Safari/537.36",
}


class ChromeUserAgent:
    def __init__(self, os: Literal["macOS", "Windows"], chrome_major_version: int):
        self.chrome_major_version = chrome_major_version
        self.os = os

    def __str__(self):
        return USER_AGENTS[self.os].format(chrome_version=self.chrome_major_version)

    @property
    def sec_ch_ua_headers(self) -> dict:
        return {
            "sec-ch-ua": f'"Google Chrome";v="{self.chrome_major_version}",'
                         f' "Chromium";v="{self.chrome_major_version}",'
                         f' "Not.A/Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": f'"{self.os}"',
        }

    @classmethod
    def from_str(cls, useragent: str) -> "ChromeUserAgent":
        pattern = r"Chrome/(\d+)"
        match = re.search(pattern, useragent)
        if not match:
            raise ValueError(f"Cannot parse Chrome version from user-agent: {useragent}")
        version = int(match.group(1))
        if "Macintosh" in useragent:
            os = "macOS"
        elif "Windows NT" in useragent:
            os = "Windows"
        else:
            raise ValueError("Unsupported useragent")
        return cls(os, version)


class ChromeAsyncSession(httpx.AsyncClient):
    def __init__(
        self,
        *,
        proxy: str | Proxy = None,
        os: Literal["macOS", "Windows"] = "Windows",
        chrome_major_version: int = 136,
        timeout: httpx.Timeout = None,
        **kwargs,
    ):
        self._proxy = Proxy.from_str(proxy) if proxy else None
        self._user_agent = ChromeUserAgent(os, chrome_major_version)

        kwargs["headers"]: dict = kwargs.get("headers", None) or {}
        kwargs["headers"].update({"user-agent": str(self._user_agent)})
        kwargs["headers"].update(self._user_agent.sec_ch_ua_headers)
        kwargs["headers"].update({
            "accept-language": "en-US,en",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "connection": "keep-alive",
        })

        super().__init__(
            proxy=self._proxy.as_url if self._proxy else None,
            timeout=timeout or httpx.Timeout(10.0),
            **kwargs,
        )

    @property
    def user_agent_obj(self) -> ChromeUserAgent | None:
        return self._user_agent

    @property
    def user_agent(self) -> str:
        return self.headers["user-agent"]

    @property
    def proxy(self) -> Proxy | None:
        return self._proxy

    @proxy.setter
    def proxy(self, proxy: str | Proxy):
        self._proxy = Proxy.from_str(proxy)
        self._mounts = {URLPattern("all://"): httpx.AsyncHTTPTransport(proxy=self._proxy.as_url)}

    def randomize_nodemaven_proxy_sid(self):
        if not self.proxy:
            raise ValueError("No proxy specified")

        self.proxy = self.proxy.copy_with_randomized_nodemaven_sid()

    def randomize_detectexpert_proxy_sid(self):
        if not self.proxy:
            raise ValueError("No proxy specified")

        self.proxy = self.proxy.copy_with_randomized_detectexpert_sid()

    def increment_proxy_seller_port(self):
        if not self.proxy:
            raise ValueError("No proxy specified")

        if self.proxy.host != "res.proxy-seller.io":
            raise ValueError(f"You must use the proxy-seller.io proxy."
                             f" Your host: '{self.proxy.host}'")

        new_port = (self.proxy.port % 65535) + 1
        self.proxy = self.proxy.model_copy(update={"port": new_port})

    def get_cookies_list(self) -> list[CookieDict]:
        return [
            CookieDict(
                name=cookie.name,
                value=cookie.value,
                domain=cookie.domain,
                path=cookie.path,
                expires=cookie.expires or 0,
                secure=cookie.secure,
                session=not cookie.expires,
                httpOnly=False,
                sameSite="unspecified",
            )
            for cookie in self.cookies.jar
        ]

    def update_cookies_from_list(self, cookies: list[CookieDict]):
        for cookie in cookies:
            self.cookies.jar.set_cookie(Cookie(
                version=0,
                name=cookie["name"],
                value=cookie["value"],
                port=None,
                port_specified=False,
                domain=cookie["domain"],
                domain_specified=True if cookie["domain"] else False,
                domain_initial_dot=bool(cookie["domain"].startswith(".")),
                path=cookie["path"],
                path_specified=bool(cookie["path"]),
                secure=cookie["secure"],
                # using if explicitly to make it clear.
                expires=None if cookie["expires"] == 0 else cookie["expires"],
                discard=cookie["expires"] == 0,
                comment=None,
                comment_url=None,
                rest=dict(http_only=f"{cookie['httpOnly']}"),
                rfc2109=False,
            ))
        self.cookies.jar.clear_expired_cookies()

    def set_cookie(
        self,
        name: str,
        value: str,
        domain: str = "",
        path: str = "/",
        expires: float = None,
        secure=False,
    ) -> None:
        """
        Set a cookie value by name. May optionally include domain and path.
        """
        if name.startswith("__Secure-") and secure is False:
            warnings.warn(
                "`secure` changed to True for `__Secure-` prefixed cookies",
                stacklevel=2,
            )
            secure = True
        elif name.startswith("__Host-") and (secure is False or domain or path != "/"):
            warnings.warn(
                "`host` changed to True, `domain` removed, `path` changed to `/` "
                "for `__Host-` prefixed cookies",
                stacklevel=2,
            )
            secure = True
            domain = ""
            path = "/"

        kwargs = {
            "version": 0,
            "name": name,
            "value": value,
            "port": None,
            "port_specified": False,
            "domain": domain,
            "domain_specified": bool(domain),
            "domain_initial_dot": domain.startswith("."),
            "path": path,
            "path_specified": bool(path),
            "secure": secure,
            "expires": expires,
            "discard": True,
            "comment": None,
            "comment_url": None,
            "rest": {"HttpOnly": None},
            "rfc2109": False,
        }
        self.cookies.jar.set_cookie(Cookie(**kwargs))


class ChromeClient:
    def __init__(
        self,
        **session_kwargs,
    ):
        self._session = ChromeAsyncSession(**session_kwargs)

    async def close(self):
        await self._session.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


async def _is_skip_retry(
        retry_options: RetryOptionsBase,
        current_attempt: int,
        response: httpx.Response,
) -> bool:
    if current_attempt == retry_options.attempts:
        return True

    if response.request.method.upper() not in retry_options.methods:
        return True

    if response.status_code >= 500 and retry_options.retry_all_server_errors:
        return False

    if response.status_code in retry_options.statuses:
        return False

    if retry_options.evaluate_response_callback is None:
        return True

    return await retry_options.evaluate_response_callback(response)


class ChromeRetryClient(ChromeClient):
    def __init__(
        self,
        retry_options: RetryOptionsBase | None = None,
        **session_kwargs,
    ):
        super().__init__(**session_kwargs)
        self._retry_options = retry_options or ExponentialRetry()

    @property
    def retry_options(self):
        return self._retry_options

    async def request_with_retry(
        self,
        method: str,
        url: str,
        follow_redirects: bool = False,
        retry_options: RetryOptionsBase | None = None,
        **request_kwargs,
    ):
        if retry_options is None:
            retry_options = self._retry_options

        request = self._session.build_request(method, url, **request_kwargs)

        current_attempt = 0

        while True:
            # print(f"Attempt {current_attempt + 1} out of {retry_options.attempts}")

            current_attempt += 1
            try:
                response = await self._session.send(request, follow_redirects=follow_redirects)

                # debug_message = f"Retrying after response code: {response.status_code}"
                skip_retry = await _is_skip_retry(retry_options, current_attempt, response)

                if skip_retry:
                    return response

                retry_wait = self._retry_options.get_timeout(attempt=current_attempt, response=response)

            except Exception as exc:
                if current_attempt >= self._retry_options.attempts:
                    raise

                is_exc_valid = any(isinstance(exc, retry_exc) for retry_exc in self._retry_options.exceptions)
                if not is_exc_valid:
                    raise

                # debug_message = f"Retrying after exception: {exc!r}"
                retry_wait = self._retry_options.get_timeout(attempt=current_attempt, response=None)

            # print(debug_message)
            await asyncio.sleep(retry_wait)
