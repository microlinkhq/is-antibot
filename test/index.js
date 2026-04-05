'use strict'

const test = require('ava')

const isAntibot = require('../src')

test('cloudflare (cf-mitigated header)', t => {
  const headers = { 'cf-mitigated': 'challenge' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
  t.is(result.detection, 'headers')
})

test('cloudflare (cf_clearance set-cookie)', t => {
  const headers = { 'set-cookie': 'cf_clearance=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
  t.is(result.detection, 'cookies')
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

test('akamai (akamai-grn header)', t => {
  const headers = { 'akamai-grn': 'test123' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
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
})

test('shapesecurity (html)', t => {
  const html = '<script>shapesecurity.init();</script>'
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'shapesecurity')
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
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
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

test('imperva (incap_ses_ set-cookie)', t => {
  const headers = { 'set-cookie': 'incap_ses_123=abc; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (visid_incap_ set-cookie)', t => {
  const headers = { 'set-cookie': 'visid_incap_456=xyz; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (reese84 set-cookie)', t => {
  const headers = { 'set-cookie': 'reese84=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
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
  const result = isAntibot({ html })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('recaptcha (no false positive for grecaptcha badge css)', t => {
  const html =
    '<style>.grecaptcha-badge{visibility:hidden}</style><title>My Video - YouTube</title>'
  const result = isAntibot({ html })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('recaptcha (html g-recaptcha)', t => {
  const html = '<div class="g-recaptcha" data-sitekey="test"></div>'
  const result = isAntibot({ html })
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

test('aws-waf (header)', t => {
  const headers = { 'x-amzn-waf-action': 'CHALLENGE' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
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

test('aws-waf (aws-waf-token set-cookie)', t => {
  const headers = { 'set-cookie': 'aws-waf-token=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('createTestPattern with invalid regex catches error', t => {
  const { createTestPattern } = require('../src')
  const has = createTestPattern('test')
  t.is(has('[invalid(regex', true), false)
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
  const result = isAntibot({ body: '<script>grecaptcha.execute();</script>' })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})
