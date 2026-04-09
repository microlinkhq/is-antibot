"""Detect antibot protection from 30+ providers."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger("is_antibot")

# Detection type constants
_HEADERS = "headers"
_COOKIES = "cookies"
_HTML = "html"
_URL = "url"
_STATUS_CODE = "status_code"


@dataclass(frozen=True)
class AntibotResult:
    """Result of antibot detection."""

    detected: bool
    provider: str | None
    detection: str | None


def _create_get_header(headers: Mapping[str, str | list[str] | None]):
    """Create a header getter function."""
    return lambda name: headers.get(name)


def create_test_pattern(value: str | None):
    """Create a pattern checker for the given value.

    Returns a function that checks whether a pattern (regex or string)
    matches the given value.
    """
    if not value:
        return lambda pattern: False
    lower_value = value.lower()

    def test(pattern: re.Pattern[str] | str) -> bool:
        if isinstance(pattern, re.Pattern):
            try:
                return pattern.search(value) is not None
            except Exception:
                return False
        return pattern.lower() in lower_value

    return test


def _split_set_cookie_string(cookie_str: str | list[str] | None) -> list[str]:
    """Split a Set-Cookie header string into individual cookie strings.

    Handles comma-separated cookies while correctly preserving commas in
    Expires date values. Port of the cookie-es splitSetCookieString algorithm.
    """
    if cookie_str is None:
        return []
    if isinstance(cookie_str, list):
        return cookie_str
    if not cookie_str:
        return []

    cookies: list[str] = []
    pos = 0
    start = 0
    length = len(cookie_str)

    while pos < length:
        # Scan for the next comma
        while pos < length and cookie_str[pos] != ",":
            pos += 1

        if pos >= length:
            break

        # Found a comma at pos. Look ahead to see if next token is a cookie name (has '=')
        lookahead = pos + 1
        # skip whitespace
        while lookahead < length and cookie_str[lookahead] == " ":
            lookahead += 1

        # Find next '=' or ';' to determine if this starts a new cookie
        scan = lookahead
        is_new_cookie = False
        while scan < length:
            ch = cookie_str[scan]
            if ch == "=":
                is_new_cookie = True
                break
            if ch == ";" or ch == ",":
                break
            scan += 1

        if is_new_cookie:
            # This comma separates two cookies
            cookies.append(cookie_str[start:pos].strip())
            start = pos + 1
            # skip whitespace after comma
            while start < length and cookie_str[start] == " ":
                start += 1
            pos = start
        else:
            # Comma is part of a date value (e.g., "Thu, 26-Mar-26 ...")
            pos += 1

    # Append the remaining segment
    remaining = cookie_str[start:].strip()
    if remaining:
        cookies.append(remaining)

    return cookies


def create_has_cookie(headers: Mapping[str, str | list[str] | None]):
    """Create a function that checks for cookie presence in Set-Cookie headers.

    Returns a function that takes a cookie prefix pattern and returns True if
    any Set-Cookie value starts with that pattern.
    """
    cookies = _split_set_cookie_string(headers.get("set-cookie"))

    def has_cookie(pattern: str) -> bool:
        return any(c.startswith(pattern) for c in cookies)

    return has_cookie


def _get_header_names(headers: Mapping[str, str | list[str] | None]) -> list[str]:
    """Return all header names as a list."""
    return list(headers.keys())


def _get_domain(url: str) -> str:
    """Extract the registrable domain from a URL (e.g. 'www.reddit.com' -> 'reddit.com')."""
    hostname = urlparse(url).hostname or ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


# Pre-compiled regex patterns
_RE_SHAPE_HEADER = re.compile(r"^x-[a-z0-9]{8}-[abcdfz]$", re.IGNORECASE)
_RE_CHEQZONE = re.compile(r"cheqzone\.com", re.IGNORECASE)
_RE_CHEQ_AI = re.compile(r"cheq\.ai", re.IGNORECASE)
_RE_MEETRICS = re.compile(r"meetrics\.com", re.IGNORECASE)
_RE_OCULE = re.compile(r"ocule\.co\.uk", re.IGNORECASE)
_RE_GOOGLE_RECAPTCHA = re.compile(r"google\.com/recaptcha", re.IGNORECASE)
_RE_GRECAPTCHA_API = re.compile(
    r"\b(?:window\.)?grecaptcha\s*\.(?:execute|render|ready|getResponse|enterprise)\b", re.IGNORECASE
)
_RE_GRECAPTCHA_CALL = re.compile(r"\b(?:window\.)?grecaptcha\s*\(", re.IGNORECASE)
_RE_GRECAPTCHA_CFG = re.compile(r"\b__grecaptcha_cfg\b", re.IGNORECASE)
_RE_HCAPTCHA = re.compile(r"hcaptcha\.com", re.IGNORECASE)
_RE_ARKOSELABS = re.compile(r"arkoselabs\.com", re.IGNORECASE)
_RE_GEETEST = re.compile(r"geetest\.com", re.IGNORECASE)
_RE_CF_TURNSTILE = re.compile(r"challenges\.cloudflare\.com/turnstile", re.IGNORECASE)
_RE_FRIENDLY_CAPTCHA = re.compile(r"friendlycaptcha\.com", re.IGNORECASE)
_RE_CAPTCHA_EU = re.compile(r"captcha\.eu", re.IGNORECASE)
_RE_QCLOUD = re.compile(r"turing\.captcha\.qcloud\.com", re.IGNORECASE)
_RE_ALIEXPRESS = re.compile(r"punish\?x5secdata", re.IGNORECASE)
_RE_REDDIT_BLOCKED = re.compile(r"blocked by network security\.", re.IGNORECASE)
_RE_INSTAGRAM_LOGIN = re.compile(r"<title>\s*Login\s*[•·]\s*Instagram\s*</title>", re.IGNORECASE)
_RE_YOUTUBE_EMPTY = re.compile(r"<title>\s*-\s*YouTube</title>", re.IGNORECASE)
_RE_ANUBIS_SCRIPT = re.compile(r'<script id="anubis_challenge"')


def _detect(
    headers: Mapping[str, str | list[str] | None],
    html: str,
    url: str,
    status_code: int | None,
) -> AntibotResult:
    """Run the full detection chain. Returns on first match."""
    get_header = _create_get_header(headers)
    has_cookie = create_has_cookie(headers)
    html_has = create_test_pattern(html)
    url_has = create_test_pattern(url)

    def has_any_header(header_names: list[str]) -> bool:
        return any(get_header(name) for name in header_names)

    def has_any_cookie(cookie_names: list[str]) -> bool:
        return any(has_cookie(name) for name in cookie_names)

    def has_any_html(patterns: list[re.Pattern[str] | str]) -> bool:
        return any(html_has(p) for p in patterns)

    def has_any_url(patterns: list[re.Pattern[str] | str]) -> bool:
        return any(url_has(p) for p in patterns)

    def by_headers(provider: str) -> AntibotResult:
        return _create_result(True, provider, _HEADERS)

    def by_cookies(provider: str) -> AntibotResult:
        return _create_result(True, provider, _COOKIES)

    def by_html(provider: str) -> AntibotResult:
        return _create_result(True, provider, _HTML)

    def by_url(provider: str) -> AntibotResult:
        return _create_result(True, provider, _URL)

    def by_status_code(provider: str) -> AntibotResult:
        return _create_result(True, provider, _STATUS_CODE)

    # Cloudflare: Check for cf-mitigated header with 'challenge' value
    # Official docs: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
    if get_header("cf-mitigated") == "challenge":
        return by_headers("cloudflare")

    # Cloudflare: cf_clearance cookie indicates Cloudflare challenge flow
    if has_any_cookie(["cf_clearance="]):
        return by_cookies("cloudflare")

    # Vercel: Check for x-vercel-mitigated header with 'challenge' value
    # Solver reference: https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
    if get_header("x-vercel-mitigated") == "challenge":
        return by_headers("vercel")

    # Akamai: Check for akamai-cache-status header starting with 'Error'
    # Official docs: https://techdocs.akamai.com/property-mgr/docs/return-cache-status
    akamai_cache = get_header("akamai-cache-status")
    if akamai_cache and str(akamai_cache).startswith("Error"):
        return by_headers("akamai")

    # Akamai: Check for additional identifying headers (akamai-grn, x-akamai-session-info)
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-akamai.json
    if has_any_header(["akamai-grn", "x-akamai-session-info"]):
        return by_headers("akamai")

    # Akamai: _abck bot manager tracking cookie
    if has_any_cookie(["_abck="]):
        return by_cookies("akamai")

    # Akamai: Bot Manager API namespace (bmak) in html
    if has_any_html(["bmak."]):
        return by_html("akamai")

    # DataDome: Check for x-dd-b header with values '1' (soft challenge) or '2' (hard challenge/CAPTCHA)
    # Official docs: https://docs.datadome.co/reference/validate-request
    if get_header("x-dd-b") in ("1", "2"):
        return by_headers("datadome")

    # DataDome: x-datadome header presence.
    # Note: `x-datadome: protected` can appear on successful responses.
    x_datadome = get_header("x-datadome")
    if x_datadome and str(x_datadome).lower() != "protected":
        return by_headers("datadome")

    # DataDome: x-datadome-cid header presence
    if has_any_header(["x-datadome-cid"]):
        return by_headers("datadome")

    # DataDome: datadome tracking cookie
    if has_any_cookie(["datadome="]):
        return by_cookies("datadome")

    # PerimeterX: Check for X-PX-Authorization header (primary indicator)
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-perimeterx.json
    if get_header("x-px-authorization"):
        return by_headers("perimeterx")

    # PerimeterX: Check for window._pxAppId, pxInit, or _pxAction in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-perimeterx.json
    if has_any_html(["window._pxAppId", "pxInit", "_pxAction"]):
        return by_html("perimeterx")

    # PerimeterX: _px3 or _pxhd cookies
    if has_any_cookie(["_px3=", "_pxhd="]):
        return by_cookies("perimeterx")

    # Shape Security: Check for dynamic header patterns x-[8chars]-[abcdfz]
    # These headers use 8 random characters followed by suffixes like -a, -b, -c, -d, -f, or -z
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-shapesecurity.json
    header_names = _get_header_names(headers)
    for name in header_names:
        if _RE_SHAPE_HEADER.search(name):
            return by_headers("shapesecurity")

    # Shape Security: Check for 'shapesecurity' text in response html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-shapesecurity.json
    if has_any_html(["shapesecurity"]):
        return by_html("shapesecurity")

    # Kasada: Check for x-kasada or x-kasada-challenge headers
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-kasada.json
    if has_any_header(["x-kasada", "x-kasada-challenge"]):
        return by_headers("kasada")

    # Kasada: Check for __kasada global object or kasada.js script in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-kasada.json
    if has_any_html(["__kasada", "kasada.js"]):
        return by_html("kasada")

    # Imperva/Incapsula: Check for x-cdn header with 'Incapsula' value or x-iinfo header
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
    if get_header("x-cdn") == "Incapsula" or has_any_header(["x-iinfo"]):
        return by_headers("imperva")

    # Imperva/Incapsula: Check for 'incapsula' or 'imperva' text in response html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
    if has_any_html(["incapsula", "imperva"]):
        return by_html("imperva")

    # Imperva/Incapsula: incap_ses_, visid_incap_, or reese84 cookies
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
    if has_any_cookie(["incap_ses_", "visid_incap_", "reese84="]):
        return by_cookies("imperva")

    # Reblaze: rbzid or rbzsessionid cookies
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-reblaze.json
    if has_any_cookie(["rbzid=", "rbzsessionid="]):
        return by_cookies("reblaze")

    # Reblaze: Check for 'reblaze' text in response html
    if has_any_html(["reblaze"]):
        return by_html("reblaze")

    # Cheq: Check for CheqSdk or cheqzone.com in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-cheq.json
    if has_any_html(["CheqSdk", "cheqzone.com"]):
        return by_html("cheq")

    # Cheq: Check for cheqzone.com or cheq.ai in URL
    if has_any_url([_RE_CHEQZONE, _RE_CHEQ_AI]):
        return by_url("cheq")

    # Sucuri: Check for 'sucuri' text in response html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-sucuri.json
    if has_any_html(["sucuri"]):
        return by_html("sucuri")

    # ThreatMetrix: Check for 'ThreatMetrix' in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-threatmetrix.json
    if has_any_html(["ThreatMetrix"]):
        return by_html("threatmetrix")

    # ThreatMetrix: Check for fp/check.js fingerprint endpoint in URL
    if has_any_url(["fp/check.js"]):
        return by_url("threatmetrix")

    # Meetrics: Check for 'meetrics' text in response html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-meetrics.json
    if has_any_html(["meetrics"]):
        return by_html("meetrics")

    # Meetrics: Check for meetrics.com in URL
    if has_any_url([_RE_MEETRICS]):
        return by_url("meetrics")

    # Ocule: Check for ocule.co.uk in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-ocule.json
    if has_any_html(["ocule.co.uk"]):
        return by_html("ocule")

    # Ocule: Check for ocule.co.uk in URL
    if has_any_url([_RE_OCULE]):
        return by_url("ocule")

    # reCAPTCHA: Check for recaptcha/api, google.com/recaptcha, gstatic.com/recaptcha, or recaptcha.net in URL
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-recaptcha.json
    if has_any_url(["recaptcha/api", "gstatic.com/recaptcha", "recaptcha.net"]) or has_any_url([_RE_GOOGLE_RECAPTCHA]):
        return by_url("recaptcha")

    # reCAPTCHA: Check for grecaptcha API usage in html (JavaScript indicator)
    # Note: plain "grecaptcha" is too broad (e.g. ".grecaptcha-badge" CSS appears on normal YouTube pages)
    if has_any_html([_RE_GRECAPTCHA_API, _RE_GRECAPTCHA_CALL, _RE_GRECAPTCHA_CFG]):
        return by_html("recaptcha")

    # reCAPTCHA: Check for g-recaptcha container class in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-recaptcha.json
    if has_any_html(["g-recaptcha"]):
        return by_html("recaptcha")

    # hCaptcha: Check for hcaptcha.com domain in URL
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-hcaptcha.json
    if has_any_url([_RE_HCAPTCHA]):
        return by_url("hcaptcha")

    # hCaptcha: Check for hcaptcha.com API domain or h-captcha container class in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-hcaptcha.json
    # Note: bare 'hcaptcha' matches too broadly (could appear in articles discussing hCaptcha)
    if has_any_html(["hcaptcha.com", "h-captcha"]):
        return by_html("hcaptcha")

    # FunCaptcha (Arkose Labs): Check for arkoselabs.com or funcaptcha in URL
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-funcaptcha.json
    if has_any_url([_RE_ARKOSELABS]) or has_any_url(["funcaptcha"]):
        return by_url("funcaptcha")

    # FunCaptcha (Arkose Labs): Check for arkoselabs.com API domain or funcaptcha in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-funcaptcha.json
    # Note: bare 'arkose' matches too broadly (e.g. Facebook bundles Arkose SDK for login without blocking content)
    if has_any_html(["arkoselabs.com", "funcaptcha"]):
        return by_html("funcaptcha")

    # GeeTest: Check for geetest.com domain in URL
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-geetest.json
    if has_any_url([_RE_GEETEST]):
        return by_url("geetest")

    # GeeTest: Check for geetest object or text in html
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-geetest.json
    # Note: bare 'gt.js' removed (too generic, any script named gt.js would match)
    if has_any_html(["geetest"]):
        return by_html("geetest")

    # Cloudflare Turnstile: Check for challenges.cloudflare.com/turnstile in URL
    if has_any_url([_RE_CF_TURNSTILE]):
        return by_url("cloudflare-turnstile")

    # Cloudflare Turnstile: Check for cf-turnstile class or turnstile API script in html
    # Note: bare 'turnstile' matches too broadly (common English word)
    if has_any_html(["cf-turnstile", "challenges.cloudflare.com/turnstile"]):
        return by_html("cloudflare-turnstile")

    # Friendly Captcha: Check for friendlycaptcha.com in URL
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-friendlycaptcha.json
    if has_any_url([_RE_FRIENDLY_CAPTCHA]):
        return by_url("friendly-captcha")

    # Friendly Captcha: Check for frc-captcha container or friendlyChallenge object in html
    if has_any_html(["frc-captcha", "friendlyChallenge"]):
        return by_html("friendly-captcha")

    # Captcha.eu: Check for captcha.eu in URL
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-captchaeu.json
    if has_any_url([_RE_CAPTCHA_EU]):
        return by_url("captcha-eu")

    # Captcha.eu: Check for CaptchaEU or captchaeu in html
    if has_any_html(["CaptchaEU", "captchaeu"]):
        return by_html("captcha-eu")

    # QCloud Captcha (Tencent): Check for turing.captcha.qcloud.com in URL
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-qcloud.json
    if has_any_url([_RE_QCLOUD]):
        return by_url("qcloud-captcha")

    # QCloud Captcha: Check for TencentCaptcha or turing.captcha in html
    if has_any_html(["TencentCaptcha", "turing.captcha"]):
        return by_html("qcloud-captcha")

    # AliExpress CAPTCHA: Check for punish?x5secdata in URL
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-aliexpress.json
    if has_any_url([_RE_ALIEXPRESS]):
        return by_url("aliexpress-captcha")

    # AliExpress CAPTCHA: Check for x5secdata in html
    if has_any_html(["x5secdata"]):
        return by_html("aliexpress-captcha")

    # Reddit: blocked requests are served as HTML challenge pages.
    if _get_domain(url) == "reddit.com":
        if status_code == 403:
            return by_status_code("reddit")
        if has_any_html([_RE_REDDIT_BLOCKED]):
            return by_html("reddit")

    # LinkedIn: status 999 is LinkedIn's dedicated bot-detection response
    if _get_domain(url) == "linkedin.com" and status_code == 999:
        return by_status_code("linkedin")

    # Instagram: login page redirect indicates bot detection
    if _get_domain(url) == "instagram.com" and has_any_html([_RE_INSTAGRAM_LOGIN]):
        return by_html("instagram")

    # YouTube: empty title pattern indicates a degraded response requiring BotGuard JS attestation
    # Normal pages have `<title>Video Title - YouTube</title>`, bots get `<title> - YouTube</title>`
    if has_any_html([_RE_YOUTUBE_EMPTY]):
        return by_html("youtube")

    # Anubis (Techaro BotStopper): challenge pages always contain the JSON script block
    # `<script id="anubis_challenge" type="application/json">` (hardcoded in web/index.templ)
    # and asset/API URLs under the Go constant `StaticPath = "/.within.website/x/cmd/anubis/"`.
    # Source: https://github.com/TecharoHQ/anubis
    if has_any_html([_RE_ANUBIS_SCRIPT, "/.within.website/x/cmd/anubis/"]):
        return by_html("anubis")

    # AWS WAF: Check for x-amzn-waf-action or x-amzn-requestid headers
    # Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-aws-waf.json
    if has_any_header(["x-amzn-waf-action", "x-amzn-requestid"]):
        return by_headers("aws-waf")

    # AWS WAF: Check for aws-waf or awswaf text in html
    if has_any_html(["aws-waf", "awswaf"]):
        return by_html("aws-waf")

    # AWS WAF: aws-waf-token cookie
    if has_any_cookie(["aws-waf-token="]):
        return by_cookies("aws-waf")

    return _create_result(False, None, None)


def _create_result(detected: bool, provider: str | None, detection: str | None) -> AntibotResult:
    """Create and log an antibot detection result."""
    logger.debug("detected=%s provider=%s detection=%s", detected, provider, detection)
    return AntibotResult(detected=detected, provider=provider, detection=detection)


def is_antibot(
    *,
    headers: Mapping[str, str | list[str] | None] | None = None,
    html: str | None = None,
    body: str | None = None,
    url: str | None = None,
    status_code: int | None = None,
    status: int | None = None,
) -> AntibotResult:
    """Detect antibot protection from response data.

    Args:
        headers: Response headers as a dict-like mapping.
        html: Response HTML body.
        body: Alias for html.
        url: The request URL.
        status_code: HTTP status code.
        status: Alias for status_code.

    Returns:
        AntibotResult with detected, provider, and detection fields.
    """
    return _detect(
        headers=headers or {},
        html=html or body or "",
        url=url or "",
        status_code=status_code if status_code is not None else status,
    )


__all__ = ["is_antibot", "create_test_pattern", "create_has_cookie", "AntibotResult"]
