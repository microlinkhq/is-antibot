'use strict'

const test = require('ava')

const isAntibot = require('../src')

test('cloudflare (cf-mitigated header)', t => {
  const headers = { 'cf-mitigated': 'challenge' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
})

test('cloudflare (cf_clearance set-cookie)', t => {
  const headers = { 'set-cookie': 'cf_clearance=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
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

test('akamai (bmak in body)', t => {
  const body = '<script>bmak.sensor_data = "test";</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
})

test('akamai (no antibot)', t => {
  const headers = { 'akamai-cache-status': 'HIT' }
  const result = isAntibot({ headers })
  t.is(result.detected, false)
  t.is(result.provider, null)
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

test('perimeterx (body window._pxAppId)', t => {
  const body = '<script>window._pxAppId = "PX123";</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
})

test('perimeterx (body pxInit)', t => {
  const body = '<script>pxInit();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
})

test('perimeterx (body _pxAction)', t => {
  const body = '<script>var _pxAction = "c";</script>'
  const result = isAntibot({ body })
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

test('shapesecurity (body)', t => {
  const body = '<script>shapesecurity.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'shapesecurity')
})

test('kasada (header)', t => {
  const headers = { 'x-kasada': 'test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'kasada')
})

test('kasada (body)', t => {
  const body = '<script>__kasada.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'kasada')
})

test('imperva (header)', t => {
  const headers = { 'x-cdn': 'Incapsula' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (body with incapsula)', t => {
  const body = '<script>incapsula.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('imperva (body with imperva)', t => {
  const body = '<script>imperva.protect();</script>'
  const result = isAntibot({ body })
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

test('reblaze (body)', t => {
  const body = '<p>Protected by Reblaze</p>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'reblaze')
})

test('cheq (body CheqSdk)', t => {
  const body = '<script>CheqSdk.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'cheq')
})

test('cheq (body cheqzone.com)', t => {
  const body = '<script src="https://ob.cheqzone.com/script.js"></script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'cheq')
})

test('cheq (url cheqzone.com)', t => {
  const url = 'https://ob.cheqzone.com/script.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'cheq')
})

test('cheq (url cheq.ai)', t => {
  const url = 'https://cheq.ai/api/verify'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'cheq')
})

test('sucuri (body)', t => {
  const body = '<p>Sucuri Website Firewall - Access Denied</p>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'sucuri')
})

test('threatmetrix (body)', t => {
  const body = '<script>ThreatMetrix.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'threatmetrix')
})

test('threatmetrix (url fp/check.js)', t => {
  const url = 'https://example.com/fp/check.js?org_id=abc'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'threatmetrix')
})

test('meetrics (body)', t => {
  const body = '<script>meetricsGlobal.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'meetrics')
})

test('meetrics (url)', t => {
  const url = 'https://s418.mxcdn.net/bb-mx/serve/meetrics.com/script'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'meetrics')
})

test('ocule (body)', t => {
  const body = '<script src="https://proxy.ocule.co.uk/script.js"></script>'
  const result = isAntibot({ body })
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

test('recaptcha (body grecaptcha)', t => {
  const body = '<script>grecaptcha.execute();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('recaptcha (body g-recaptcha)', t => {
  const body = '<div class="g-recaptcha" data-sitekey="test"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('hcaptcha (url)', t => {
  const url = 'https://hcaptcha.com/captcha/v1'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
})

test('hcaptcha (body hcaptcha)', t => {
  const body = '<div data-hcaptcha="test"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
})

test('hcaptcha (body h-captcha)', t => {
  const body = '<div class="h-captcha"></div>'
  const result = isAntibot({ body })
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

test('funcaptcha (body with funcaptcha)', t => {
  const body = '<script>funcaptcha.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'funcaptcha')
})

test('funcaptcha (body with arkose)', t => {
  const body = '<script>window.arkoseCallback();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'funcaptcha')
})

test('geetest (url)', t => {
  const url = 'https://api.geetest.com/ajax.php'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'geetest')
})

test('geetest (body)', t => {
  const body = '<script>geetest.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'geetest')
})

test('geetest (body with gt.js)', t => {
  const body = '<script src="/static/gt.js"></script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'geetest')
})

test('cloudflare-turnstile (url)', t => {
  const url = 'https://challenges.cloudflare.com/turnstile/v0/api.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
})

test('cloudflare-turnstile (body cf-turnstile)', t => {
  const body = '<div class="cf-turnstile"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
})

test('cloudflare-turnstile (body turnstile)', t => {
  const body = '<script>window.turnstile.render();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
})

test('friendly-captcha (url)', t => {
  const url = 'https://cdn.friendlycaptcha.com/modules/v2/widget.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'friendly-captcha')
})

test('friendly-captcha (body frc-captcha)', t => {
  const body = '<div class="frc-captcha" data-sitekey="test"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'friendly-captcha')
})

test('friendly-captcha (body friendlyChallenge)', t => {
  const body = '<script>friendlyChallenge.render();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'friendly-captcha')
})

test('captcha-eu (url)', t => {
  const url = 'https://www.captcha.eu/widget/api.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'captcha-eu')
})

test('captcha-eu (body CaptchaEU)', t => {
  const body = '<script>CaptchaEU.render();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'captcha-eu')
})

test('captcha-eu (body captchaeu)', t => {
  const body = '<div class="captchaeu-widget"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'captcha-eu')
})

test('qcloud-captcha (url)', t => {
  const url = 'https://turing.captcha.qcloud.com/tdc.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'qcloud-captcha')
})

test('qcloud-captcha (body TencentCaptcha)', t => {
  const body = '<script>new TencentCaptcha("appid");</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'qcloud-captcha')
})

test('qcloud-captcha (body turing.captcha)', t => {
  const body = '<script src="//turing.captcha.gtimg.com/tdc.js"></script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'qcloud-captcha')
})

test('aliexpress-captcha (url)', t => {
  const url = 'https://www.aliexpress.com/punish?x5secdata=abc123'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'aliexpress-captcha')
})

test('aliexpress-captcha (body)', t => {
  const body = '<script>var x5secdata = "abc123";</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'aliexpress-captcha')
})

test('linkedin (got set-cookie as array)', t => {
  const headers = {
    'set-cookie': [
      'trkCode=bf; Max-Age=5',
      'trkInfo=AQFAratONFrB2AAAAZ0pYgFwkRxy7pe2KqithoZ4DrIdVyCD8WiY3gYONBobD4g7t-PWmVWJzN28GTO7ZeKfrcPmTti_uaSFN-8qXScyFz-hE-pBpGPZuyIRSsqcCtg0OsMdUX4=; Max-Age=5',
      'rtc=AQEVeAM-pHq_2QAAAZ0pYgFw6by_4L6d1QzyV8pieP39_RzmN8vtczqYcGa2WGH5LwJWuR0JT_GsVzsuuEOaQtWxSNnLIC9ARJF3qu-Ym5hkaxkL5Ciaa-WN264N2_xsawkGjX-snaZ4Nx0GGWEZlPzoNaX_ODWeNpbln_P6yWOykLOwSxcWtPLlGKRV8g4iubY9Rr0GiFUhTSsNXgxnOFfqnXA=; Max-Age=120; path=/; domain=.linkedin.com',
      '__cf_bm=SMqN8mDteTetWk0K04HDlr8GBw_7.aINZ4GPOztm3H8-1774515782-1.0.1.1-ei2drbbibbsB.7gExLK7sOcjkxwFxQA.4tWMyU0isXPg8lzPuBGYKIb94wx9uKBfHQWb0eNRKOlTZKb.KE227rK9Vje15fD3gYHFG2bpnvA; path=/; expires=Thu, 26-Mar-26 09:33:02 GMT; domain=.linkedin.com; HttpOnly; Secure; SameSite=None'
    ]
  }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'linkedin')
})

test('linkedin (fetch set-cookie as comma-joined string)', t => {
  const headers = {
    'set-cookie': 'trkCode=bf; Max-Age=5, trkInfo=AQFyonFtUZqc7AAAAZ0pYrzwPDR4VFZ_9p6fG0FvEcRgl8OPYOi_BuI0UjU5CWQ8ajOcRDP94FWd1WG6ml4bCIeTNo529UZFwMB_Pit8kSdbz5IzaPaVV0VLYrO1HwPhyu2APN4=; Max-Age=5, rtc=AQEwoUg34YjbqQAAAZ0pYrzwk3vgeorXn_hlwqY4LaH634gq_kHjFzZC_qrYXquN4zzqX50dVT8cqdcMbfyhAdu3RA6gjC6glMQah0nh9lEeiircCG43N6-oCN4kObfwug1PtZ619Yl0F3MK-TSvU3h3KYyvW4vltvXhLrxeK9DpT5AjGyD0WDPrM8KtK7w7UF9SEsTBYrpyPqcm6nfvrYY6QY0=; Max-Age=120; path=/; domain=.linkedin.com, __cf_bm=TBitBBkee9M2KOZkThR1uXuERq5RTmOKtLwnU7KxQYM-1774515830-1.0.1.1-09U1TNumW0aJGTQClLtEJRVB92lnaY0_IVz4X6E_Vulp2cS1VcnqhX81f28bwKLxPfIZ.lrkhjKn.yNK_Impgkj3QjDocla2r5PETU_QN0A; path=/; expires=Thu, 26-Mar-26 09:33:50 GMT; domain=.linkedin.com; HttpOnly; Secure; SameSite=None'
  }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'linkedin')
})

test('linkedin (no antibot without trkCode=bf)', t => {
  const headers = {
    'x-li-fabric': 'prod-lor1',
    'set-cookie': 'other=value; Max-Age=5'
  }
  const result = isAntibot({ headers })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('youtube (empty title in body)', t => {
  const body = '<!DOCTYPE html><html><head><title> - YouTube</title></head><body><ytd-app disable-upgrade="true"></ytd-app></body></html>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'youtube')
})

test('youtube (no antibot with normal title)', t => {
  const body = '<!DOCTYPE html><html><head><title>My Video - YouTube</title></head><body></body></html>'
  const result = isAntibot({ body })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('aws-waf (header)', t => {
  const headers = { 'x-amzn-waf-action': 'CHALLENGE' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('aws-waf (body aws-waf)', t => {
  const body = '<script>aws-waf.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('aws-waf (body awswaf)', t => {
  const body = '<script src="/awswaf/challenge.js"></script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('aws-waf (aws-waf-token set-cookie)', t => {
  const headers = { 'set-cookie': 'aws-waf-token=abc123; path=/' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('testPattern with invalid regex catches error', t => {
  const { testPattern } = require('../src')
  // Test with an invalid regex pattern that would throw
  const result = testPattern('test', '[invalid(regex', true)
  t.is(result, false)
})

test('testPattern with invalid regex', t => {
  const result = isAntibot({ url: 'test', body: 'test' })
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

test('support Response object', t => {
  const headers = new Map([['cf-mitigated', 'challenge']])
  // mock Headers.get
  headers.get = headers.get.bind(headers)
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
})
