"""Detect antibot protection systems from HTTP responses."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

__all__ = ["is_antibot", "AntibotResult", "create_test_pattern", "create_has_cookie"]

# ---------------------------------------------------------------------------
# Detection types
# ---------------------------------------------------------------------------

_HEADERS = "headers"
_COOKIES = "cookies"
_HTML = "html"
_URL = "url"
_STATUS_CODE = "status_code"

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AntibotResult:
    detected: bool
    provider: str | None
    detection: str | None


# ---------------------------------------------------------------------------
# Cookie splitting (port of cookie-es splitSetCookieString)
# ---------------------------------------------------------------------------


def _split_set_cookie_string(header: str | None) -> list[str]:
    if not header:
        return []

    cookies: list[str] = []
    pos = 0

    while pos < len(header):
        start = pos
        cookie_separator_found = False

        while pos < len(header):
            ch = header[pos]
            if ch == ",":
                last_comma = pos
                pos += 1
                # skip whitespace after comma
                while pos < len(header) and header[pos] == " ":
                    pos += 1
                next_start = pos

                # Check if what follows looks like a new cookie (has '=' before ';' or end)
                while pos < len(header) and header[pos] != ";" and header[pos] != ",":
                    pos += 1

                # pos is at ';', ',' or end-of-string
                if pos < len(header) and header[pos] == ";":
                    # New cookie starts at next_start
                    cookie_separator_found = True
                    pos = next_start
                    cookies.append(header[start:last_comma].strip())
                    start = next_start
                    break
                elif pos >= len(header):
                    # Check if we found '=' between next_start and pos
                    if "=" in header[next_start:pos]:
                        cookie_separator_found = True
                        pos = next_start
                        cookies.append(header[start:last_comma].strip())
                        start = next_start
                        break
                    # else continue, this comma was part of a value (e.g. date)
                else:
                    # pos is at ','  -- continue scanning
                    pass
            else:
                pos += 1

        if not cookie_separator_found:
            cookies.append(header[start:].strip())

    return [c for c in cookies if c]


# ---------------------------------------------------------------------------
# Helper: extract registered domain from URL
# ---------------------------------------------------------------------------


def _get_domain(url: str) -> str:
    """Return a simplified domain from *url* (strip leading 'www.' etc.)."""
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return ""
    # Strip leading www.
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname.lower()


# ---------------------------------------------------------------------------
# Helper factories (exported for advanced usage)
# ---------------------------------------------------------------------------


def create_test_pattern(value: str | None) -> Callable[[str | re.Pattern[str]], bool]:
    """Return a function that tests *value* against a string or regex pattern."""
    if not value:
        return lambda _pattern: False
    lower_value = value.lower()

    def _test(pattern: str | re.Pattern[str]) -> bool:
        if isinstance(pattern, re.Pattern):
            try:
                return bool(pattern.search(value))
            except Exception:
                return False
        return pattern.lower() in lower_value

    return _test


def create_has_cookie(headers: dict[str, str]) -> Callable[[str], bool]:
    """Return a function that checks whether a cookie prefix exists in Set-Cookie."""
    raw = _get_header(headers, "set-cookie")
    cookies = _split_set_cookie_string(raw)

    def _has(prefix: str) -> bool:
        return any(c.startswith(prefix) for c in cookies)

    return _has


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    # Fast path: exact match
    val = headers.get(name)
    if val is not None:
        return val
    # Slow path: case-insensitive
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


# ---------------------------------------------------------------------------
# Precompiled regex patterns
# ---------------------------------------------------------------------------

_RE_SHAPE_HEADER = re.compile(r"^x-[a-z0-9]{8}-[abcdfz]$", re.IGNORECASE)
_RE_CHEQZONE = re.compile(r"cheqzone\.com", re.IGNORECASE)
_RE_CHEQ_AI = re.compile(r"cheq\.ai", re.IGNORECASE)
_RE_MEETRICS = re.compile(r"meetrics\.com", re.IGNORECASE)
_RE_OCULE = re.compile(r"ocule\.co\.uk", re.IGNORECASE)
_RE_GOOGLE_RECAPTCHA = re.compile(r"google\.com/recaptcha", re.IGNORECASE)
_RE_HCAPTCHA = re.compile(r"hcaptcha\.com", re.IGNORECASE)
_RE_ARKOSELABS = re.compile(r"arkoselabs\.com", re.IGNORECASE)
_RE_GEETEST = re.compile(r"geetest\.com", re.IGNORECASE)
_RE_CF_TURNSTILE_URL = re.compile(
    r"challenges\.cloudflare\.com/turnstile", re.IGNORECASE
)
_RE_FRIENDLY_CAPTCHA = re.compile(r"friendlycaptcha\.com", re.IGNORECASE)
_RE_CAPTCHA_EU = re.compile(r"captcha\.eu", re.IGNORECASE)
_RE_QCLOUD = re.compile(r"turing\.captcha\.qcloud\.com", re.IGNORECASE)
_RE_ALIEXPRESS = re.compile(r"punish\?x5secdata", re.IGNORECASE)

_RE_GRECAPTCHA_EXEC = re.compile(
    r"\b(?:window\.)?grecaptcha\s*\.(?:execute|render|ready|getResponse|enterprise)\b",
    re.IGNORECASE,
)
_RE_GRECAPTCHA_CALL = re.compile(
    r"\b(?:window\.)?grecaptcha\s*\(", re.IGNORECASE
)
_RE_GRECAPTCHA_CFG = re.compile(r"\b__grecaptcha_cfg\b", re.IGNORECASE)

_RE_BLOCKED_NETWORK = re.compile(r"blocked by network security\.", re.IGNORECASE)

_RE_INSTAGRAM_LOGIN = re.compile(
    r"<title>\s*Login\s*[•·]\s*Instagram\s*</title>", re.IGNORECASE
)
_RE_YOUTUBE_EMPTY = re.compile(r"<title>\s*-\s*YouTube</title>", re.IGNORECASE)
_RE_ANUBIS_SCRIPT = re.compile(r'<script id="anubis_challenge"')


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def _detect(
    headers: dict[str, str],
    html: str,
    url: str,
    status_code: int | None,
) -> AntibotResult:
    has_cookie = create_has_cookie(headers)
    html_has = create_test_pattern(html)
    url_has = create_test_pattern(url)

    def has_any_header(names: list[str]) -> bool:
        return any(_get_header(headers, n) is not None for n in names)

    def has_any_cookie(prefixes: list[str]) -> bool:
        return any(has_cookie(p) for p in prefixes)

    def has_any_html(patterns: list[str | re.Pattern[str]]) -> bool:
        return any(html_has(p) for p in patterns)

    def has_any_url(patterns: list[str | re.Pattern[str]]) -> bool:
        return any(url_has(p) for p in patterns)

    def by_headers(provider: str) -> AntibotResult:
        return AntibotResult(True, provider, _HEADERS)

    def by_cookies(provider: str) -> AntibotResult:
        return AntibotResult(True, provider, _COOKIES)

    def by_html(provider: str) -> AntibotResult:
        return AntibotResult(True, provider, _HTML)

    def by_url(provider: str) -> AntibotResult:
        return AntibotResult(True, provider, _URL)

    def by_status_code(provider: str) -> AntibotResult:
        return AntibotResult(True, provider, _STATUS_CODE)

    # -- Cloudflare --
    if _get_header(headers, "cf-mitigated") == "challenge":
        return by_headers("cloudflare")

    if has_any_cookie(["cf_clearance="]):
        return by_cookies("cloudflare")

    # -- Vercel --
    if _get_header(headers, "x-vercel-mitigated") == "challenge":
        return by_headers("vercel")

    # -- Akamai --
    akamai_cache = _get_header(headers, "akamai-cache-status")
    if akamai_cache is not None and akamai_cache.startswith("Error"):
        return by_headers("akamai")

    if has_any_header(["akamai-grn", "x-akamai-session-info"]):
        return by_headers("akamai")

    if has_any_cookie(["_abck="]):
        return by_cookies("akamai")

    if has_any_html(["bmak."]):
        return by_html("akamai")

    # -- DataDome --
    xddb = _get_header(headers, "x-dd-b")
    if xddb in ("1", "2"):
        return by_headers("datadome")

    x_datadome = _get_header(headers, "x-datadome")
    if x_datadome is not None and x_datadome.lower() != "protected":
        return by_headers("datadome")

    if has_any_header(["x-datadome-cid"]):
        return by_headers("datadome")

    if has_any_cookie(["datadome="]):
        return by_cookies("datadome")

    # -- PerimeterX --
    if _get_header(headers, "x-px-authorization") is not None:
        return by_headers("perimeterx")

    if has_any_html(["window._pxAppId", "pxInit", "_pxAction"]):
        return by_html("perimeterx")

    if has_any_cookie(["_px3=", "_pxhd="]):
        return by_cookies("perimeterx")

    # -- Shape Security --
    for name in headers:
        if _RE_SHAPE_HEADER.match(name):
            return by_headers("shapesecurity")

    if has_any_html(["shapesecurity"]):
        return by_html("shapesecurity")

    # -- Kasada --
    if has_any_header(["x-kasada", "x-kasada-challenge"]):
        return by_headers("kasada")

    if has_any_html(["__kasada", "kasada.js"]):
        return by_html("kasada")

    # -- Imperva / Incapsula --
    if _get_header(headers, "x-cdn") == "Incapsula" or has_any_header(["x-iinfo"]):
        return by_headers("imperva")

    if has_any_html(["incapsula", "imperva"]):
        return by_html("imperva")

    if has_any_cookie(["incap_ses_", "visid_incap_", "reese84="]):
        return by_cookies("imperva")

    # -- Reblaze --
    if has_any_cookie(["rbzid=", "rbzsessionid="]):
        return by_cookies("reblaze")

    if has_any_html(["reblaze"]):
        return by_html("reblaze")

    # -- Cheq --
    if has_any_html(["CheqSdk", "cheqzone.com"]):
        return by_html("cheq")

    if has_any_url([_RE_CHEQZONE, _RE_CHEQ_AI]):
        return by_url("cheq")

    # -- Sucuri --
    if has_any_html(["sucuri"]):
        return by_html("sucuri")

    # -- ThreatMetrix --
    if has_any_html(["ThreatMetrix"]):
        return by_html("threatmetrix")

    if has_any_url(["fp/check.js"]):
        return by_url("threatmetrix")

    # -- Meetrics --
    if has_any_html(["meetrics"]):
        return by_html("meetrics")

    if has_any_url([_RE_MEETRICS]):
        return by_url("meetrics")

    # -- Ocule --
    if has_any_html(["ocule.co.uk"]):
        return by_html("ocule")

    if has_any_url([_RE_OCULE]):
        return by_url("ocule")

    # -- reCAPTCHA --
    if has_any_url(
        ["recaptcha/api", "gstatic.com/recaptcha", "recaptcha.net"]
    ) or has_any_url([_RE_GOOGLE_RECAPTCHA]):
        return by_url("recaptcha")

    if has_any_html([_RE_GRECAPTCHA_EXEC, _RE_GRECAPTCHA_CALL, _RE_GRECAPTCHA_CFG]):
        return by_html("recaptcha")

    if has_any_html(["g-recaptcha"]):
        return by_html("recaptcha")

    # -- hCaptcha --
    if has_any_url([_RE_HCAPTCHA]):
        return by_url("hcaptcha")

    if has_any_html(["hcaptcha.com", "h-captcha"]):
        return by_html("hcaptcha")

    # -- FunCaptcha (Arkose Labs) --
    if has_any_url([_RE_ARKOSELABS]) or has_any_url(["funcaptcha"]):
        return by_url("funcaptcha")

    if has_any_html(["arkoselabs.com", "funcaptcha"]):
        return by_html("funcaptcha")

    # -- GeeTest --
    if has_any_url([_RE_GEETEST]):
        return by_url("geetest")

    if has_any_html(["geetest"]):
        return by_html("geetest")

    # -- Cloudflare Turnstile --
    if has_any_url([_RE_CF_TURNSTILE_URL]):
        return by_url("cloudflare-turnstile")

    if has_any_html(["cf-turnstile", "challenges.cloudflare.com/turnstile"]):
        return by_html("cloudflare-turnstile")

    # -- Friendly Captcha --
    if has_any_url([_RE_FRIENDLY_CAPTCHA]):
        return by_url("friendly-captcha")

    if has_any_html(["frc-captcha", "friendlyChallenge"]):
        return by_html("friendly-captcha")

    # -- Captcha.eu --
    if has_any_url([_RE_CAPTCHA_EU]):
        return by_url("captcha-eu")

    if has_any_html(["CaptchaEU", "captchaeu"]):
        return by_html("captcha-eu")

    # -- QCloud Captcha (Tencent) --
    if has_any_url([_RE_QCLOUD]):
        return by_url("qcloud-captcha")

    if has_any_html(["TencentCaptcha", "turing.captcha"]):
        return by_html("qcloud-captcha")

    # -- AliExpress CAPTCHA --
    if has_any_url([_RE_ALIEXPRESS]):
        return by_url("aliexpress-captcha")

    if has_any_html(["x5secdata"]):
        return by_html("aliexpress-captcha")

    # -- Reddit --
    if _get_domain(url) == "reddit.com":
        if status_code == 403:
            return by_status_code("reddit")
        if has_any_html([_RE_BLOCKED_NETWORK]):
            return by_html("reddit")

    # -- LinkedIn --
    if _get_domain(url) == "linkedin.com" and status_code == 999:
        return by_status_code("linkedin")

    # -- Instagram --
    if _get_domain(url) == "instagram.com" and has_any_html([_RE_INSTAGRAM_LOGIN]):
        return by_html("instagram")

    # -- YouTube --
    if has_any_html([_RE_YOUTUBE_EMPTY]):
        return by_html("youtube")

    # -- Anubis (Techaro BotStopper) --
    if has_any_html([_RE_ANUBIS_SCRIPT, "/.within.website/x/cmd/anubis/"]):
        return by_html("anubis")

    # -- AWS WAF --
    if has_any_header(["x-amzn-waf-action", "x-amzn-requestid"]):
        return by_headers("aws-waf")

    if has_any_html(["aws-waf", "awswaf"]):
        return by_html("aws-waf")

    if has_any_cookie(["aws-waf-token="]):
        return by_cookies("aws-waf")

    return AntibotResult(False, None, None)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_antibot(
    *,
    headers: dict[str, str] | None = None,
    html: str | None = None,
    body: str | None = None,
    url: str | None = None,
    status_code: int | None = None,
    status: int | None = None,
) -> AntibotResult:
    """Detect antibot protection from HTTP response data.

    Parameters
    ----------
    headers:
        Response headers as a dict.
    html:
        Response body as a string (takes precedence over *body*).
    body:
        Alias for *html*.
    url:
        The final response URL (after redirects).
    status_code:
        HTTP status code (takes precedence over *status*).
    status:
        Alias for *status_code*.

    Returns
    -------
    AntibotResult
        A frozen dataclass with ``detected``, ``provider``, and ``detection``.
    """
    return _detect(
        headers=headers or {},
        html=html if html is not None else (body or ""),
        url=url or "",
        status_code=status_code if status_code is not None else status,
    )
