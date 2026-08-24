'use strict'

const test = require('ava')

const isAntibot = require('../src')

test('cloudflare (cf-mitigated header)', t => {
  const headers = { 'cf-mitigated': 'challenge' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
  t.is(result.detection, 'headers')
  t.is(result.technique, 'javascript')
})

test('cloudflare (cf_clearance set-cookie)', t => {
  const headers = { 'set-cookie': 'cf_clearance=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
  t.is(result.detection, 'cookies')
  t.is(result.technique, 'cookie')
})

test('cloudflare (html _cf_chl_opt interstitial)', t => {
  const html = '<script>window._cf_chl_opt={cvId:"2"};</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
  t.is(result.detection, 'html')
  t.is(result.technique, 'javascript')
})

test('cloudflare (no false positive for jsd beacon)', t => {
  const html =
    "<script>window.__CF$cv$params={r:'abc'};a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';</script>"
  t.is(isAntibot({ html, statusCode: 200 }).detected, false)
  t.is(isAntibot({ html, statusCode: 403 }).detected, false)
})

test('cloudflare (no false positive for cdn-cgi email protection)', t => {
  const html = '<a href="/cdn-cgi/l/email-protection">email</a>'
  const result = isAntibot({ html, statusCode: 403 })
  t.is(result.detected, false)
})

test('cloudflare (no false positive for bare cloudflare mention)', t => {
  const html = '<p>We use Cloudflare CDN.</p>'
  const result = isAntibot({ html, statusCode: 403 })
  t.is(result.detected, false)
})

test('vercel', t => {
  const headers = { 'x-vercel-mitigated': 'challenge' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'vercel')
})

test('akamai (akamai-cache-status error)', t => {
  const headers = { 'akamai-cache-status': 'Error from child' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
})

test('akamai (akamai-grn header alone is not antibot)', t => {
  // akamai-grn is a per-request CDN trace id present on every Akamai-fronted
  // response; on its own it is not a bot challenge (e.g. msn.com serves full
  // content with this header). A real signal must be present instead.
  const headers = { 'akamai-grn': 'test123' }
  const result = isAntibot({ headers })
  t.is(result.detected, false)
  t.is(result.provider, null)
  t.is(result.detection, null)
})

test('akamai (_abck set-cookie)', t => {
  const headers = { 'set-cookie': '_abck=abc123~0~; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
})

test('akamai (bmak in html)', t => {
  const html = '<script>bmak.sensor_data = "test";</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
})

test('akamai (no antibot)', t => {
  const headers = { 'akamai-cache-status': 'HIT' }
  const result = isAntibot({ headers })
  t.is(result.detected, false)
  t.is(result.provider, null)
  t.is(result.detection, null)
})

test('datadome (x-dd-b header)', t => {
  for (const value of ['1', '2']) {
    const headers = { 'x-dd-b': value }
    const result = isAntibot({ headers })
    t.is(result.detected, true, `should detect datadome for x-dd-b=${value}`)
    t.is(result.provider, 'datadome')
  }
})

test('datadome (x-datadome header)', t => {
  const headers = { 'x-datadome': 'test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'datadome')
})

test('datadome (x-datadome protected is not enough)', t => {
  const headers = { 'x-datadome': 'protected' }
  const result = isAntibot({ headers })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('datadome (x-datadome-cid header)', t => {
  const headers = { 'x-datadome-cid': 'abc123' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'datadome')
})

test('datadome (set-cookie)', t => {
  const headers = { 'set-cookie': 'datadome=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'datadome')
})

test('perimeterx (header)', t => {
  const headers = { 'x-px-authorization': 'test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
})

test('perimeterx (html window._pxAppId)', t => {
  const html = '<script>window._pxAppId = "PX123";</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
})

test('perimeterx (html pxInit)', t => {
  const html = '<script>pxInit();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
})

test('perimeterx (html _pxAction)', t => {
  const html = '<script>var _pxAction = "c";</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
})

test('perimeterx (_px3 set-cookie)', t => {
  const headers = { 'set-cookie': '_px3=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
})

test('perimeterx (_pxhd set-cookie)', t => {
  const headers = { 'set-cookie': '_pxhd=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
})

test('shapesecurity (header)', t => {
  const headers = { 'x-abc12345-a': 'test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'shapesecurity')
  t.is(result.technique, 'javascript')
})

test('shapesecurity (html)', t => {
  const html = '<script>shapesecurity.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'shapesecurity')
})

test('shapesecurity (no false positive for bare mention)', t => {
  const html = '<p>shapesecurity (now F5) writeup</p>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('kasada (header)', t => {
  const headers = { 'x-kasada': 'test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'kasada')
})

test('kasada (html)', t => {
  const html = '<script>__kasada.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'kasada')
})

test('imperva (header)', t => {
  const headers = { 'x-cdn': 'Incapsula' }
  const result = isAntibot({ headers, statusCode: 403 })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (fronting headers on a served page are not a block)', t => {
  const headers = { 'x-cdn': 'Incapsula', 'x-iinfo': '39-6829515-6829577 NNYN' }
  const html = '<html><body>real content</body></html>'
  for (const statusCode of [200, 301, 404]) {
    const result = isAntibot({ headers, html, statusCode })
    t.is(result.detected, false, `statusCode ${statusCode}`)
  }
})

test('imperva (challenge interstitial is a block on a 200)', t => {
  const html =
    '<html><head><script src="/_Incapsula_Resource?SWJIYLWA=5074a744e2e3d891814e9a2dace20bd4,719d34d31c8e3a6e6fffd425f7e032f3"></script></head><body></body></html>'
  const result = isAntibot({ html, statusCode: 200 })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
  t.is(result.technique, 'javascript')
})

test('imperva (telemetry script on a served page is not a block)', t => {
  const html =
    '<html><body>real content<script src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e6fffd425f7e032f3&ns=1&cb=673101135"></script></body></html>'
  const result = isAntibot({ html, statusCode: 200 })
  t.is(result.detected, false)
})

test('imperva (html with incapsula)', t => {
  const html = '<script>incapsula.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (html with imperva)', t => {
  const html = '<script>imperva.protect();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (no false positive for bare mention)', t => {
  const html =
    '<footer>Security powered by Imperva</footer><p>We migrated from Incapsula.</p>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('imperva (incap_ses_ set-cookie)', t => {
  const headers = { 'set-cookie': 'incap_ses_123=abc; path=/' }
  const result = isAntibot({ headers, statusCode: 403 })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (incap_ses_ on a served page is not a block)', t => {
  const headers = { 'set-cookie': 'incap_ses_123=abc; path=/' }
  const result = isAntibot({
    headers,
    html: '<html>ok</html>',
    statusCode: 200
  })
  t.is(result.detected, false)
})

test('imperva (visid_incap_ set-cookie)', t => {
  const headers = { 'set-cookie': 'visid_incap_456=xyz; path=/' }
  const result = isAntibot({ headers, statusCode: 403 })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (visid_incap_ on a served page is not a block)', t => {
  const headers = { 'set-cookie': 'visid_incap_456=xyz; path=/' }
  const result = isAntibot({
    headers,
    html: '<html>ok</html>',
    statusCode: 200
  })
  t.is(result.detected, false)
})

test('imperva (reese84 set-cookie)', t => {
  const headers = { 'set-cookie': 'reese84=abc123; path=/' }
  const result = isAntibot({ headers, statusCode: 403 })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (reese84 on a served page is not a block)', t => {
  const headers = { 'set-cookie': 'reese84=abc123; path=/' }
  const result = isAntibot({
    headers,
    html: '<html>ok</html>',
    statusCode: 200
  })
  t.is(result.detected, false)
})

test('reblaze (rbzid set-cookie)', t => {
  const headers = { 'set-cookie': 'rbzid=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'reblaze')
})

test('reblaze (rbzsessionid set-cookie)', t => {
  const headers = { 'set-cookie': 'rbzsessionid=xyz; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'reblaze')
})

test('reblaze (html)', t => {
  const html = '<p>Protected by Reblaze</p>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'reblaze')
  t.is(result.detection, 'html')
})

test('reblaze (no false positive for bare mention)', t => {
  const html = '<p>Reblaze vs Cloudflare comparison</p>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('cheq (html CheqSdk)', t => {
  const html = '<script>CheqSdk.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'cheq')
})

test('cheq (html cheqzone.com)', t => {
  const html = '<script src="https://ob.cheqzone.com/script.js"></script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'cheq')
})

test('cheq (url cheqzone.com)', t => {
  const url = 'https://ob.cheqzone.com/script.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'cheq')
  t.is(result.detection, 'url')
})

test('cheq (url cheq.ai)', t => {
  const url = 'https://cheq.ai/api/verify'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'cheq')
})

test('sucuri (html)', t => {
  const html = '<p>Sucuri Website Firewall - Access Denied</p>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'sucuri')
})

test('sucuri (no false positive for badge / bare mention)', t => {
  const html = '<a href="https://sitecheck.sucuri.net/">Scanned by Sucuri</a>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('threatmetrix (html)', t => {
  const html = '<script>ThreatMetrix.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'threatmetrix')
})

test('threatmetrix (url fp/check.js)', t => {
  const url = 'https://example.com/fp/check.js?org_id=abc'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'threatmetrix')
})

test('threatmetrix (html, not a false positive on config keys)', t => {
  // Netflix embeds feature-flag config keys mentioning threatmetrix in the page
  // JSON. These are not an antibot challenge: the device-profiling tag is only
  // active when the ThreatMetrix JS API is invoked (e.g. ThreatMetrix.init()).
  const html =
    '{"enable.threatmetrix.debug":true,"enable.threatmetrix.onload.timeout":6000}'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('meetrics (html)', t => {
  const html = '<script>meetricsGlobal.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'meetrics')
})

test('meetrics (url)', t => {
  const url = 'https://s418.mxcdn.net/bb-mx/serve/meetrics.com/script'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'meetrics')
})

test('meetrics (no false positive for bare mention)', t => {
  const html =
    '<script>var x={"vendor":"meetrics"}</script><h1>Real article</h1>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('ocule (html)', t => {
  const html = '<script src="https://proxy.ocule.co.uk/script.js"></script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'ocule')
})

test('ocule (url)', t => {
  const url = 'https://proxy.ocule.co.uk/script.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'ocule')
})

test('recaptcha (url with recaptcha/api)', t => {
  const url = 'https://www.google.com/recaptcha/api.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('recaptcha (url with google.com/recaptcha)', t => {
  const url = 'https://google.com/recaptcha/enterprise.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('recaptcha (url with gstatic.com/recaptcha)', t => {
  const url = 'https://www.gstatic.com/recaptcha/releases/abc/recaptcha.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('recaptcha (url with recaptcha.net)', t => {
  const url = 'https://recaptcha.net/recaptcha/api.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('recaptcha (html grecaptcha)', t => {
  const html = '<script>grecaptcha.execute();</script>'
  const result = isAntibot({ html, statusCode: 429 })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
  t.is(result.technique, 'captcha')
})

test('recaptcha (v3 on a served page is not a block)', t => {
  const html =
    '<script>grecaptcha.ready(function () { grecaptcha.execute("6Ldl") })</script>'
  const result = isAntibot({ html, statusCode: 200 })
  t.is(result.detected, false)
})

test('recaptcha (no false positive for grecaptcha badge css)', t => {
  const html =
    '<style>.grecaptcha-badge{visibility:hidden}</style><title>My Video - YouTube</title>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('recaptcha (html g-recaptcha on a blocking status)', t => {
  const html = '<div class="g-recaptcha" data-sitekey="test"></div>'
  for (const statusCode of [403, 429, 503]) {
    const result = isAntibot({ html, statusCode })
    t.is(result.detected, true, `should detect for status ${statusCode}`)
    t.is(result.provider, 'recaptcha')
  }
})

test('recaptcha (no false positive: g-recaptcha widget on a 200 content page)', t => {
  // Sites embed a reCAPTCHA login/contact widget on fully-rendered content pages; the bare
  // widget alone (status 200) is not a block — only a blocking status or active grecaptcha is.
  const html =
    '<html><body><article>real content</article><div class="c-form-group g-recaptcha" data-sitekey="k"></div></body></html>'
  const result = isAntibot({ html, statusCode: 200 })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('recaptcha (html active grecaptcha on a 200 page is still a block)', t => {
  const html =
    '<div class="g-recaptcha"></div><script>grecaptcha.render("x")</script>'
  const result = isAntibot({ html, statusCode: 200 })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('hcaptcha (url)', t => {
  const url = 'https://hcaptcha.com/captcha/v1'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
})

test('hcaptcha (html hcaptcha.com)', t => {
  const html = '<script src="https://hcaptcha.com/1/api.js"></script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
})

test('hcaptcha (no false positive for bare hcaptcha mention)', t => {
  const html = '<p>We use hcaptcha for bot protection.</p>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('hcaptcha (html h-captcha)', t => {
  const html = '<div class="h-captcha"></div>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
})

test('funcaptcha (url with arkoselabs)', t => {
  const url = 'https://client-api.arkoselabs.com/fc/gc/'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'funcaptcha')
})

test('funcaptcha (url with funcaptcha)', t => {
  const url = 'https://api.funcaptcha.com/fc/gt2/public_key/test'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'funcaptcha')
})

test('funcaptcha (html with funcaptcha)', t => {
  const html = '<script>funcaptcha.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'funcaptcha')
})

test('funcaptcha (no false positive for bare funcaptcha mention)', t => {
  const html = '<p>funcaptcha is now called Arkose.</p>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('funcaptcha (html with arkoselabs.com)', t => {
  const html =
    '<script src="https://client-api.arkoselabs.com/fc/assets/loader.js"></script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'funcaptcha')
})

test('funcaptcha (no false positive for bare arkose mention)', t => {
  const html =
    '<script>window.__arkose_config = {};</script><meta property="og:title" content="Real content">'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('geetest (url)', t => {
  const url = 'https://api.geetest.com/ajax.php'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'geetest')
})

test('geetest (html)', t => {
  const html = '<script>geetest.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'geetest')
})

test('geetest (no false positive for generic gt.js)', t => {
  const html = '<script src="/static/gt.js"></script>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('geetest (no false positive for bare mention)', t => {
  const html = '<p>We evaluated geetest for our login.</p>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('cloudflare-turnstile (url)', t => {
  const url = 'https://challenges.cloudflare.com/turnstile/v0/api.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
})

test('cloudflare-turnstile (html cf-turnstile)', t => {
  const html = '<div class="cf-turnstile"></div>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
})

test('cloudflare-turnstile (html turnstile API)', t => {
  const html =
    '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
})

test('cloudflare-turnstile (no false positive for bare turnstile word)', t => {
  const html = '<p>The subway turnstile was broken.</p>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('friendly-captcha (url)', t => {
  const url = 'https://cdn.friendlycaptcha.com/modules/v2/widget.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'friendly-captcha')
})

test('friendly-captcha (html frc-captcha)', t => {
  const html = '<div class="frc-captcha" data-sitekey="test"></div>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'friendly-captcha')
})

test('friendly-captcha (html friendlyChallenge)', t => {
  const html = '<script>friendlyChallenge.render();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'friendly-captcha')
})

test('captcha-eu (url)', t => {
  const url = 'https://www.captcha.eu/widget/api.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'captcha-eu')
})

test('captcha-eu (html CaptchaEU)', t => {
  const html = '<script>CaptchaEU.render();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'captcha-eu')
})

test('captcha-eu (html captchaeu)', t => {
  const html = '<div class="captchaeu-widget"></div>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'captcha-eu')
})

test('qcloud-captcha (url)', t => {
  const url = 'https://turing.captcha.qcloud.com/tdc.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'qcloud-captcha')
})

test('qcloud-captcha (html TencentCaptcha)', t => {
  const html = '<script>new TencentCaptcha("appid");</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'qcloud-captcha')
})

test('qcloud-captcha (html turing.captcha)', t => {
  const html = '<script src="//turing.captcha.gtimg.com/tdc.js"></script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'qcloud-captcha')
})

test('aliexpress-captcha (url)', t => {
  const url = 'https://www.aliexpress.com/punish?x5secdata=abc123'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'aliexpress-captcha')
})

test('aliexpress-captcha (html)', t => {
  const html = '<script>var x5secdata = "abc123";</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'aliexpress-captcha')
})

test('houzz (blocked by status code)', t => {
  // Houzz rate-limits datacenter IPs with a bare 429 "too many requests" page
  // that carries no antibot fingerprint. Scope the status rule to the domain so
  // an origin fetch surfacing a 429 escalates to the residential proxy.
  const url =
    'https://www.houzz.com/photos/primary-bathroom-retreat-transitional-bathroom-london-phvw-vp~210219633'
  const html = '<html><body>\n429 Error too many requests \n</body></html>'
  const result = isAntibot({ url, html, statusCode: 429 })
  t.is(result.detected, true)
  t.is(result.provider, 'houzz')
  t.is(result.detection, 'statusCode')
  t.is(result.technique, 'waf')
})

test('houzz (429 on non-houzz url should not match)', t => {
  const result = isAntibot({
    url: 'https://example.com/some/path',
    statusCode: 429
  })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('houzz (200 on houzz url should not match)', t => {
  const url = 'https://www.houzz.com/photos/x~210219633'
  const result = isAntibot({
    url,
    html: '<html><body>ok</body></html>',
    statusCode: 200
  })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('reddit (blocked html)', t => {
  const html = '<div>blocked by network security.</div>'
  const url =
    'https://www.reddit.com/r/lotus/comments/1pzbv0z/my_lotus_elise_72d_with_17_rays_volk_gtp/'
  const result = isAntibot({ html, url })
  t.is(result.detected, true)
  t.is(result.provider, 'reddit')
  t.is(result.detection, 'html')
})

test('reddit (blocked html on non-reddit url should not match)', t => {
  const html = '<div>blocked by network security.</div>'
  const url = 'https://example.com/some/path'
  const result = isAntibot({ html, url })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('reddit (blocked by status code)', t => {
  const headers = {
    'content-type': 'text/html',
    server: 'snooserv',
    'cache-control': 'private, no-store'
  }
  const url =
    'https://www.reddit.com/r/digitalnomad/comments/1riz2r5/i_love_mexico_city_but_i_feel_so_unhealthy_here/'
  const result = isAntibot({ headers, url, statusCode: 403 })
  t.is(result.detected, true)
  t.is(result.provider, 'reddit')
  t.is(result.detection, 'statusCode')
})

test('reddit (allowed endpoint)', t => {
  const headers = {
    'content-type': 'application/json; charset=UTF-8',
    server: 'snooserv'
  }
  const url =
    'https://www.reddit.com/r/lotus/comments/1pzbv0z/my_lotus_elise_72d_with_17_rays_volk_gtp/'
  const result = isAntibot({ headers, url })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('reddit (please wait for verification interstitial)', t => {
  const html =
    '<html><head><title>Reddit - Please wait for verification</title></head><body></body></html>'
  const url = 'https://www.reddit.com/user/kikobeats/'
  const result = isAntibot({ html, url, statusCode: 200 })
  t.is(result.detected, true)
  t.is(result.provider, 'reddit')
  t.is(result.detection, 'html')
})

test('weibo (sina visitor system gate)', t => {
  const html =
    '<html><head><title>Sina Visitor System</title></head><body></body></html>'
  const url = 'https://m.weibo.cn/u/2803301701'
  const result = isAntibot({ html, url, statusCode: 200 })
  t.is(result.detected, true)
  t.is(result.provider, 'weibo')
  t.is(result.detection, 'html')
})

test('weibo (gate marker on non-weibo url should not match)', t => {
  const html = '<html><head><title>Sina Visitor System</title></head></html>'
  const result = isAntibot({ html, url: 'https://example.com/some/path' })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('dribbble (403 forbidden to bots)', t => {
  const result = isAntibot({
    statusCode: 403,
    url: 'https://dribbble.com/omidnikrah'
  })
  t.is(result.detected, true)
  t.is(result.provider, 'dribbble')
  t.is(result.detection, 'statusCode')
})

test('dribbble (403 with CloudFront error header stays dribbble)', t => {
  const result = isAntibot({
    statusCode: 403,
    url: 'https://dribbble.com/omidnikrah',
    headers: { 'x-cache': 'Error from cloudfront' }
  })
  t.is(result.detected, true)
  t.is(result.provider, 'dribbble')
})

test('douban (image cdn 418 without referer)', t => {
  const result = isAntibot({
    statusCode: 418,
    url: 'https://img1.doubanio.com/icon/ul1000001-30.jpg'
  })
  t.is(result.detected, true)
  t.is(result.provider, 'douban')
  t.is(result.detection, 'statusCode')
})

test('linkedin (status 999)', t => {
  const result = isAntibot({
    statusCode: 999,
    url: 'https://www.linkedin.com/in/wesbos'
  })
  t.is(result.detected, true)
  t.is(result.provider, 'linkedin')
  t.is(result.detection, 'statusCode')
})

test('linkedin (status 999 ignored for non-linkedin url)', t => {
  const result = isAntibot({ statusCode: 999, url: 'https://example.com' })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('linkedin (no antibot without status 999)', t => {
  const headers = {
    'x-li-fabric': 'prod-lor1',
    'set-cookie': 'other=value; Max-Age=5'
  }
  const result = isAntibot({ headers, statusCode: 200 })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('instagram (login page redirect)', t => {
  const html =
    '<!DOCTYPE html><html lang="en"><head><title>Login \u2022 Instagram</title></head><body></body></html>'
  const result = isAntibot({
    html,
    url: 'https://www.instagram.com/kikobeats/'
  })
  t.is(result.detected, true)
  t.is(result.provider, 'instagram')
  t.is(result.detection, 'html')
})

test('youtube (empty title in html)', t => {
  const html =
    '<!DOCTYPE html><html><head><title> - YouTube</title></head><body><ytd-app disable-upgrade="true"></ytd-app></body></html>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'youtube')
})

test('youtube (no antibot with normal title)', t => {
  const html =
    '<!DOCTYPE html><html><head><title>My Video - YouTube</title></head><body></body></html>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('anubis (html anubis_challenge script tag)', t => {
  const html =
    '<script id="anubis_challenge" type="application/json">{"rules":{"algorithm":"metarefresh"}}</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'anubis')
  t.is(result.detection, 'html')
})

test('anubis (html static path)', t => {
  const html =
    '<img src="https://example.com/.within.website/x/cmd/anubis/static/img/pensive.webp">'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'anubis')
  t.is(result.detection, 'html')
})

test('anubis (no false positive for anubis_challenge in plain text)', t => {
  const html = '<p>The template uses anubis_challenge as a key</p>'
  const result = isAntibot({ html, headers: {} })
  t.is(result.detected, false)
})

test('anubis (no false positive for anubis_challenge as non-script element)', t => {
  const html = '<div id="anubis_challenge">some content</div>'
  const result = isAntibot({ html, headers: {} })
  t.is(result.detected, false)
})

test('anubis (no false positive for within.website in html text)', t => {
  const html = '<p>Read more at within.website blog</p>'
  const result = isAntibot({ html, headers: {} })
  t.is(result.detected, false)
})

test('anubis (regex is case-sensitive)', t => {
  const html =
    '<SCRIPT id="anubis_challenge" type="application/json">{"rules":{"algorithm":"metarefresh"}}</SCRIPT>'
  const result = isAntibot({ html, headers: {} })
  t.is(result.detected, false)
})

test('amazon (x-cache Error from cloudfront + amazon URL + status 500)', t => {
  const result = isAntibot({
    url: 'https://www.amazon.com/dp/B000000000',
    headers: { 'x-cache': 'Error from cloudfront' },
    statusCode: 500
  })
  t.is(result.detected, true)
  t.is(result.provider, 'amazon')
  t.is(result.detection, 'headers')
})

test('amazon (no match without status 500)', t => {
  const result = isAntibot({
    url: 'https://www.amazon.com/dp/B000000000',
    headers: { 'x-cache': 'Error from cloudfront' },
    statusCode: 200
  })
  t.is(result.detected, false)
})

test('amazon (no match when statusCode omitted)', t => {
  const result = isAntibot({
    url: 'https://www.amazon.com/dp/B000000000',
    headers: { 'x-cache': 'Error from cloudfront' }
  })
  t.is(result.detected, false)
})

test('amazon (captcha page with csm-captcha-instrumentation)', t => {
  const result = isAntibot({
    url: 'https://www.amazon.es/-/en/Earpads-Earbuds/dp/B0FSKMP53K',
    html: '<script src="https://images-eu.ssl-images-amazon.com/images/G/01/csminstrumentation/csm-captcha-instrumentation.min.js"></script>',
    statusCode: 200
  })
  t.is(result.detected, true)
  t.is(result.provider, 'amazon')
  t.is(result.detection, 'html')
})

test('amazon (csm-captcha-instrumentation on non-amazon URL should not match)', t => {
  const result = isAntibot({
    url: 'https://example.com/page',
    html: '<script src="https://images-eu.ssl-images-amazon.com/images/G/01/csminstrumentation/csm-captcha-instrumentation.min.js"></script>',
    statusCode: 200
  })
  t.is(result.detected, false)
})

test('amazon (cloudfront error off amazon is not amazon)', t => {
  const result = isAntibot({
    url: 'https://example.com/',
    headers: { 'x-cache': 'Error from cloudfront' },
    statusCode: 403
  })
  t.not(result.provider, 'amazon')
  t.is(result.provider, 'cloudfront')
})

test('cloudfront (x-cache Error from cloudfront)', t => {
  const result = isAntibot({
    url: 'https://www.un.org/en/about-us',
    headers: { 'x-cache': 'Error from cloudfront' },
    statusCode: 403
  })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudfront')
  t.is(result.technique, 'waf')
})

test('cloudfront (html error page on 403)', t => {
  const result = isAntibot({
    url: 'https://www.un.org/en/about-us',
    html: '<title>ERROR: The request could not be satisfied</title>',
    statusCode: 403
  })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudfront')
  t.is(result.technique, 'waf')
})

test('cloudfront (no false positive: Error from cloudfront on 200)', t => {
  const result = isAntibot({
    url: 'https://www.un.org/en/about-us',
    headers: { 'x-cache': 'Error from cloudfront' },
    statusCode: 200
  })
  t.is(result.detected, false)
})

test('cloudfront (no false positive: Miss from cloudfront on 200)', t => {
  const result = isAntibot({
    url: 'https://www.un.org/en/about-us',
    headers: { 'x-cache': 'Miss from cloudfront' },
    html: '<title>About Us | United Nations</title>',
    statusCode: 200
  })
  t.is(result.detected, false)
})

test('cloudfront (no false positive: error copy on a 200 page)', t => {
  const result = isAntibot({
    url: 'https://example.com/cloudfront-errors',
    html: '<p>The request could not be satisfied. CloudFront returns this when the request is blocked.</p>',
    statusCode: 200
  })
  t.is(result.detected, false)
})

test('fullstory-challenge (html _fs-ch- asset path)', t => {
  const html =
    '<title>Client Challenge</title><link href="/_fs-ch-1T1wmsGaOgGaSxcX/assets/styles.css" rel="stylesheet" />'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'fullstory-challenge')
  t.is(result.detection, 'html')
})

test('fullstory-challenge (cookie)', t => {
  const headers = {
    'set-cookie': '_fs_ch_st_FSBmUei20MqUiJb9=Aa-8rem4vo; Path=/'
  }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'fullstory-challenge')
  t.is(result.detection, 'cookies')
})

test('fullstory-challenge (no false positive for Client Challenge without _fs-ch-)', t => {
  const html = '<h1>Client Challenge Management Portal</h1>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('aws-waf (header)', t => {
  const headers = { 'x-amzn-waf-action': 'CHALLENGE' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
  t.is(result.technique, 'javascript')
})

test('aws-waf (html aws-waf)', t => {
  const html = '<script>aws-waf.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('aws-waf (html awswaf)', t => {
  const html = '<script src="/awswaf/challenge.js"></script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('aws-waf (no false positive for bare mention)', t => {
  const html = '<p>How to configure aws-waf rules in awswaf docs</p>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
})

test('aws-waf (aws-waf-token set-cookie)', t => {
  const headers = { 'set-cookie': 'aws-waf-token=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('createTestPattern with invalid regex catches error', t => {
  const { createTestPattern } = require('../src')
  const has = createTestPattern('test')
  t.is(has('[invalid(regex'), false)
})

test('testPattern with invalid regex', t => {
  const result = isAntibot({ url: 'test', html: 'test' })
  // Should not throw and should return no detection
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('general (no antibot)', t => {
  const result = isAntibot({ headers: {} })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('no headers provided', t => {
  const result = isAntibot()
  t.is(result.detected, false)
  t.is(result.provider, null)
  t.is(result.detection, null)
  t.is(result.technique, null)
})

test('support Headers object', t => {
  const headers = new Map([['cf-mitigated', 'challenge']])
  // mock Headers.get
  headers.get = headers.get.bind(headers)
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
})

test('support Response object (headers only)', t => {
  const headers = new Map([['cf-mitigated', 'challenge']])
  headers.get = headers.get.bind(headers)
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
})

test('support Fetch Response with await text()', async t => {
  const response = new Response('<script>grecaptcha.execute();</script>', {
    headers: { 'x-dd-b': '2' }
  })
  const html = await response.text()
  const result = isAntibot({
    headers: response.headers,
    html,
    url: response.url
  })
  t.is(result.detected, true)
  t.is(result.provider, 'datadome')
})

test('fallback body string to html', t => {
  const result = isAntibot({
    body: '<script src="https://hcaptcha.com/1/api.js"></script>'
  })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
})
