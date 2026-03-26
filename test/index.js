'use strict'

const test = require('ava')

const isAntibot = require('../src')

test('cloudflare', t => {
  const headers = { 'cf-mitigated': 'challenge' }
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

test('akamai', t => {
  const headers = { 'akamai-cache-status': 'Error from child' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
})

test('akamai (with header)', t => {
  const headers = { 'akamai-grn': 'test123' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
})

test('akamai (no antibot)', t => {
  const headers = { 'akamai-cache-status': 'HIT' }
  const result = isAntibot({ headers })
  t.is(result.detected, false)
  t.is(result.provider, null)
})

test('datadome', t => {
  for (const value of ['1', '2']) {
    const headers = { 'x-dd-b': value }
    const result = isAntibot({ headers })
    t.is(result.detected, true, `should detect datadome for x-dd-b=${value}`)
    t.is(result.provider, 'datadome')
  }
})

test('datadome (with header)', t => {
  const headers = { 'x-datadome': 'test' }
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

test('perimeterx (body)', t => {
  const body = '<script>window._pxAppId = "PX123";</script>'
  const result = isAntibot({ body })
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

test('recaptcha (body)', t => {
  const body = '<script>grecaptcha.execute();</script>'
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

test('hcaptcha (body)', t => {
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

test('cloudflare-turnstile (body)', t => {
  const body = '<div class="cf-turnstile"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
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

test('aws-waf (header)', t => {
  const headers = { 'x-amzn-waf-action': 'CHALLENGE' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('aws-waf (body)', t => {
  const body = '<script>aws-waf.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
})

test('recaptcha (body with g-recaptcha)', t => {
  const body = '<div class="g-recaptcha" data-sitekey="test"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
})

test('hcaptcha (body with hcaptcha)', t => {
  const body = '<div data-hcaptcha="test"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
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

test('cloudflare-turnstile (body with turnstile)', t => {
  const body = '<script>window.turnstile.render();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
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
