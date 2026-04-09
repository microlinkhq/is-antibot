"""Provider detection tests — port of test/index.js."""

from __future__ import annotations

from is_antibot import create_test_pattern, is_antibot


def test_cloudflare_cf_mitigated_header():
    headers = {"cf-mitigated": "challenge"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "cloudflare"
    assert result.detection == "headers"


def test_cloudflare_cf_clearance_set_cookie():
    headers = {"set-cookie": "cf_clearance=abc123; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "cloudflare"
    assert result.detection == "cookies"


def test_vercel():
    headers = {"x-vercel-mitigated": "challenge"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "vercel"


def test_akamai_cache_status_error():
    headers = {"akamai-cache-status": "Error from child"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "akamai"


def test_akamai_grn_header():
    headers = {"akamai-grn": "test123"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "akamai"


def test_akamai_abck_set_cookie():
    headers = {"set-cookie": "_abck=abc123~0~; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "akamai"


def test_akamai_bmak_in_html():
    html = '<script>bmak.sensor_data = "test";</script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "akamai"


def test_akamai_no_antibot():
    headers = {"akamai-cache-status": "HIT"}
    result = is_antibot(headers=headers)
    assert result.detected is False
    assert result.provider is None
    assert result.detection is None


def test_datadome_x_dd_b_header():
    for value in ("1", "2"):
        headers = {"x-dd-b": value}
        result = is_antibot(headers=headers)
        assert result.detected is True, f"should detect datadome for x-dd-b={value}"
        assert result.provider == "datadome"


def test_datadome_x_datadome_header():
    headers = {"x-datadome": "test"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "datadome"


def test_datadome_x_datadome_protected_is_not_enough():
    headers = {"x-datadome": "protected"}
    result = is_antibot(headers=headers)
    assert result.detected is False
    assert result.provider is None


def test_datadome_x_datadome_cid_header():
    headers = {"x-datadome-cid": "abc123"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "datadome"


def test_datadome_set_cookie():
    headers = {"set-cookie": "datadome=abc123; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "datadome"


def test_perimeterx_header():
    headers = {"x-px-authorization": "test"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "perimeterx"


def test_perimeterx_html_window_pxappid():
    html = '<script>window._pxAppId = "PX123";</script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "perimeterx"


def test_perimeterx_html_pxinit():
    html = "<script>pxInit();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "perimeterx"


def test_perimeterx_html_pxaction():
    html = '<script>var _pxAction = "c";</script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "perimeterx"


def test_perimeterx_px3_set_cookie():
    headers = {"set-cookie": "_px3=abc123; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "perimeterx"


def test_perimeterx_pxhd_set_cookie():
    headers = {"set-cookie": "_pxhd=abc123; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "perimeterx"


def test_shapesecurity_header():
    headers = {"x-abc12345-a": "test"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "shapesecurity"


def test_shapesecurity_html():
    html = "<script>shapesecurity.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "shapesecurity"


def test_kasada_header():
    headers = {"x-kasada": "test"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "kasada"


def test_kasada_html():
    html = "<script>__kasada.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "kasada"


def test_imperva_header():
    headers = {"x-cdn": "Incapsula"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "imperva"


def test_imperva_html_with_incapsula():
    html = "<script>incapsula.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "imperva"


def test_imperva_html_with_imperva():
    html = "<script>imperva.protect();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "imperva"


def test_imperva_incap_ses_set_cookie():
    headers = {"set-cookie": "incap_ses_123=abc; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "imperva"


def test_imperva_visid_incap_set_cookie():
    headers = {"set-cookie": "visid_incap_456=xyz; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "imperva"


def test_imperva_reese84_set_cookie():
    headers = {"set-cookie": "reese84=abc123; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "imperva"


def test_reblaze_rbzid_set_cookie():
    headers = {"set-cookie": "rbzid=abc123; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "reblaze"


def test_reblaze_rbzsessionid_set_cookie():
    headers = {"set-cookie": "rbzsessionid=xyz; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "reblaze"


def test_reblaze_html():
    html = "<p>Protected by Reblaze</p>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "reblaze"
    assert result.detection == "html"


def test_cheq_html_cheqsdk():
    html = "<script>CheqSdk.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "cheq"


def test_cheq_html_cheqzone_com():
    html = '<script src="https://ob.cheqzone.com/script.js"></script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "cheq"


def test_cheq_url_cheqzone_com():
    url = "https://ob.cheqzone.com/script.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "cheq"
    assert result.detection == "url"


def test_cheq_url_cheq_ai():
    url = "https://cheq.ai/api/verify"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "cheq"


def test_sucuri_html():
    html = "<p>Sucuri Website Firewall - Access Denied</p>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "sucuri"


def test_threatmetrix_html():
    html = "<script>ThreatMetrix.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "threatmetrix"


def test_threatmetrix_url_fp_check_js():
    url = "https://example.com/fp/check.js?org_id=abc"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "threatmetrix"


def test_meetrics_html():
    html = "<script>meetricsGlobal.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "meetrics"


def test_meetrics_url():
    url = "https://s418.mxcdn.net/bb-mx/serve/meetrics.com/script"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "meetrics"


def test_ocule_html():
    html = '<script src="https://proxy.ocule.co.uk/script.js"></script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "ocule"


def test_ocule_url():
    url = "https://proxy.ocule.co.uk/script.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "ocule"


def test_recaptcha_url_with_recaptcha_api():
    url = "https://www.google.com/recaptcha/api.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "recaptcha"


def test_recaptcha_url_with_google_com_recaptcha():
    url = "https://google.com/recaptcha/enterprise.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "recaptcha"


def test_recaptcha_url_with_gstatic_com_recaptcha():
    url = "https://www.gstatic.com/recaptcha/releases/abc/recaptcha.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "recaptcha"


def test_recaptcha_url_with_recaptcha_net():
    url = "https://recaptcha.net/recaptcha/api.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "recaptcha"


def test_recaptcha_html_grecaptcha():
    html = "<script>grecaptcha.execute();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "recaptcha"


def test_recaptcha_no_false_positive_for_grecaptcha_badge_css():
    html = '<style>.grecaptcha-badge{visibility:hidden}</style><title>My Video - YouTube</title>'
    result = is_antibot(html=html)
    assert result.detected is False
    assert result.provider is None


def test_recaptcha_html_g_recaptcha():
    html = '<div class="g-recaptcha" data-sitekey="test"></div>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "recaptcha"


def test_hcaptcha_url():
    url = "https://hcaptcha.com/captcha/v1"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "hcaptcha"


def test_hcaptcha_html_hcaptcha_com():
    html = '<script src="https://hcaptcha.com/1/api.js"></script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "hcaptcha"


def test_hcaptcha_no_false_positive_for_bare_hcaptcha_mention():
    html = "<p>We use hcaptcha for bot protection.</p>"
    result = is_antibot(html=html)
    assert result.detected is False


def test_hcaptcha_html_h_captcha():
    html = '<div class="h-captcha"></div>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "hcaptcha"


def test_funcaptcha_url_with_arkoselabs():
    url = "https://client-api.arkoselabs.com/fc/gc/"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "funcaptcha"


def test_funcaptcha_url_with_funcaptcha():
    url = "https://api.funcaptcha.com/fc/gt2/public_key/test"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "funcaptcha"


def test_funcaptcha_html_with_funcaptcha():
    html = "<script>funcaptcha.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "funcaptcha"


def test_funcaptcha_html_with_arkoselabs_com():
    html = '<script src="https://client-api.arkoselabs.com/fc/assets/loader.js"></script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "funcaptcha"


def test_funcaptcha_no_false_positive_for_bare_arkose_mention():
    html = '<script>window.__arkose_config = {};</script><meta property="og:title" content="Real content">'
    result = is_antibot(html=html)
    assert result.detected is False


def test_geetest_url():
    url = "https://api.geetest.com/ajax.php"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "geetest"


def test_geetest_html():
    html = "<script>geetest.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "geetest"


def test_geetest_no_false_positive_for_generic_gt_js():
    html = '<script src="/static/gt.js"></script>'
    result = is_antibot(html=html)
    assert result.detected is False


def test_cloudflare_turnstile_url():
    url = "https://challenges.cloudflare.com/turnstile/v0/api.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "cloudflare-turnstile"


def test_cloudflare_turnstile_html_cf_turnstile():
    html = '<div class="cf-turnstile"></div>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "cloudflare-turnstile"


def test_cloudflare_turnstile_html_turnstile_api():
    html = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "cloudflare-turnstile"


def test_cloudflare_turnstile_no_false_positive_for_bare_turnstile_word():
    html = "<p>The subway turnstile was broken.</p>"
    result = is_antibot(html=html)
    assert result.detected is False


def test_friendly_captcha_url():
    url = "https://cdn.friendlycaptcha.com/modules/v2/widget.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "friendly-captcha"


def test_friendly_captcha_html_frc_captcha():
    html = '<div class="frc-captcha" data-sitekey="test"></div>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "friendly-captcha"


def test_friendly_captcha_html_friendlychallenge():
    html = "<script>friendlyChallenge.render();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "friendly-captcha"


def test_captcha_eu_url():
    url = "https://www.captcha.eu/widget/api.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "captcha-eu"


def test_captcha_eu_html_captchaeu():
    html = "<script>CaptchaEU.render();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "captcha-eu"


def test_captcha_eu_html_captchaeu_widget():
    html = '<div class="captchaeu-widget"></div>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "captcha-eu"


def test_qcloud_captcha_url():
    url = "https://turing.captcha.qcloud.com/tdc.js"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "qcloud-captcha"


def test_qcloud_captcha_html_tencentcaptcha():
    html = '<script>new TencentCaptcha("appid");</script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "qcloud-captcha"


def test_qcloud_captcha_html_turing_captcha():
    html = '<script src="//turing.captcha.gtimg.com/tdc.js"></script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "qcloud-captcha"


def test_aliexpress_captcha_url():
    url = "https://www.aliexpress.com/punish?x5secdata=abc123"
    result = is_antibot(url=url)
    assert result.detected is True
    assert result.provider == "aliexpress-captcha"


def test_aliexpress_captcha_html():
    html = '<script>var x5secdata = "abc123";</script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "aliexpress-captcha"


def test_reddit_blocked_html():
    html = "<div>blocked by network security.</div>"
    url = "https://www.reddit.com/r/lotus/comments/1pzbv0z/my_lotus_elise_72d_with_17_rays_volk_gtp/"
    result = is_antibot(html=html, url=url)
    assert result.detected is True
    assert result.provider == "reddit"
    assert result.detection == "html"


def test_reddit_blocked_html_on_non_reddit_url_should_not_match():
    html = "<div>blocked by network security.</div>"
    url = "https://example.com/some/path"
    result = is_antibot(html=html, url=url)
    assert result.detected is False
    assert result.provider is None


def test_reddit_blocked_by_status_code():
    headers = {
        "content-type": "text/html",
        "server": "snooserv",
        "cache-control": "private, no-store",
    }
    url = "https://www.reddit.com/r/digitalnomad/comments/1riz2r5/i_love_mexico_city_but_i_feel_so_unhealthy_here/"
    result = is_antibot(headers=headers, url=url, status_code=403)
    assert result.detected is True
    assert result.provider == "reddit"
    assert result.detection == "status_code"


def test_reddit_allowed_endpoint():
    headers = {
        "content-type": "application/json; charset=UTF-8",
        "server": "snooserv",
    }
    url = "https://www.reddit.com/r/lotus/comments/1pzbv0z/my_lotus_elise_72d_with_17_rays_volk_gtp/"
    result = is_antibot(headers=headers, url=url)
    assert result.detected is False
    assert result.provider is None


def test_linkedin_status_999():
    result = is_antibot(status_code=999, url="https://www.linkedin.com/in/wesbos")
    assert result.detected is True
    assert result.provider == "linkedin"
    assert result.detection == "status_code"


def test_linkedin_status_999_ignored_for_non_linkedin_url():
    result = is_antibot(status_code=999, url="https://example.com")
    assert result.detected is False
    assert result.provider is None


def test_linkedin_no_antibot_without_status_999():
    headers = {
        "x-li-fabric": "prod-lor1",
        "set-cookie": "other=value; Max-Age=5",
    }
    result = is_antibot(headers=headers, status_code=200)
    assert result.detected is False
    assert result.provider is None


def test_instagram_login_page_redirect():
    html = "<!DOCTYPE html><html lang=\"en\"><head><title>Login \u2022 Instagram</title></head><body></body></html>"
    result = is_antibot(html=html, url="https://www.instagram.com/kikobeats/")
    assert result.detected is True
    assert result.provider == "instagram"
    assert result.detection == "html"


def test_youtube_empty_title_in_html():
    html = (
        "<!DOCTYPE html><html><head><title> - YouTube</title></head>"
        '<body><ytd-app disable-upgrade="true"></ytd-app></body></html>'
    )
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "youtube"


def test_youtube_no_antibot_with_normal_title():
    html = "<!DOCTYPE html><html><head><title>My Video - YouTube</title></head><body></body></html>"
    result = is_antibot(html=html)
    assert result.detected is False
    assert result.provider is None


def test_anubis_html_anubis_challenge_script_tag():
    html = '<script id="anubis_challenge" type="application/json">{"rules":{"algorithm":"metarefresh"}}</script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "anubis"
    assert result.detection == "html"


def test_anubis_html_static_path():
    html = '<img src="https://example.com/.within.website/x/cmd/anubis/static/img/pensive.webp">'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "anubis"
    assert result.detection == "html"


def test_anubis_no_false_positive_for_anubis_challenge_in_plain_text():
    html = "<p>The template uses anubis_challenge as a key</p>"
    result = is_antibot(html=html, headers={})
    assert result.detected is False


def test_anubis_no_false_positive_for_anubis_challenge_as_non_script_element():
    html = '<div id="anubis_challenge">some content</div>'
    result = is_antibot(html=html, headers={})
    assert result.detected is False


def test_anubis_no_false_positive_for_within_website_in_html_text():
    html = "<p>Read more at within.website blog</p>"
    result = is_antibot(html=html, headers={})
    assert result.detected is False


def test_aws_waf_header():
    headers = {"x-amzn-waf-action": "CHALLENGE"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "aws-waf"


def test_aws_waf_html_aws_waf():
    html = "<script>aws-waf.init();</script>"
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "aws-waf"


def test_aws_waf_html_awswaf():
    html = '<script src="/awswaf/challenge.js"></script>'
    result = is_antibot(html=html)
    assert result.detected is True
    assert result.provider == "aws-waf"


def test_aws_waf_token_set_cookie():
    headers = {"set-cookie": "aws-waf-token=abc123; path=/"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "aws-waf"


def test_create_test_pattern_with_invalid_regex_catches_error():
    has = create_test_pattern("test")
    assert has("[invalid(regex") is False


def test_test_pattern_with_invalid_regex():
    result = is_antibot(url="test", html="test")
    # Should not throw and should return no detection
    assert result.detected is False
    assert result.provider is None


def test_general_no_antibot():
    result = is_antibot(headers={})
    assert result.detected is False
    assert result.provider is None


def test_no_headers_provided():
    result = is_antibot()
    assert result.detected is False
    assert result.provider is None


def test_support_dict_headers():
    """Test with plain dict headers (Python equivalent of Headers object)."""
    headers = {"cf-mitigated": "challenge"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "cloudflare"


def test_support_response_headers_only():
    """Test with dict headers simulating a Response object."""
    headers = {"cf-mitigated": "challenge"}
    result = is_antibot(headers=headers)
    assert result.detected is True
    assert result.provider == "cloudflare"


def test_support_fetch_response_with_text():
    """Test with headers dict and html body (Python equivalent of Fetch Response)."""
    headers = {"x-dd-b": "2"}
    html = "<script>grecaptcha.execute();</script>"
    result = is_antibot(headers=headers, html=html)
    assert result.detected is True
    assert result.provider == "datadome"


def test_fallback_body_string_to_html():
    result = is_antibot(body="<script>grecaptcha.execute();</script>")
    assert result.detected is True
    assert result.provider == "recaptcha"
