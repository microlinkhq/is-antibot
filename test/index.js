'use strict'

const test = require('ava')

const isAntibot = require('../src')

test('cloudflare', t => {
  const headers = { 'cf-mitigated': 'challenge' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
  t.is(result.confidence, 100)
})

test('cloudflare (with cf-ray)', t => {
  const headers = { 'cf-ray': '12345', server: 'cloudflare' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
  t.is(result.confidence, 85)
})

test('vercel', t => {
  const headers = { 'x-vercel-mitigated': 'challenge' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'vercel')
  t.is(result.confidence, 100)
})

test('akamai', t => {
  const headers = { 'akamai-cache-status': 'Error from child' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
  t.is(result.confidence, 100)
})

test('akamai (with _abck cookie)', t => {
  const headers = { cookie: '_abck=test123' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'akamai')
  t.is(result.confidence, 90)
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
    t.is(result.confidence, 100)
  }
})

test('datadome (with cookie)', t => {
  const headers = { cookie: 'datadome=test123' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'datadome')
  t.is(result.confidence, 95)
})

test('perimeterx (header)', t => {
  const headers = { 'x-px-authorization': 'test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
  t.is(result.confidence, 100)
})

test('perimeterx (cookie)', t => {
  const headers = { cookie: '_px3=test123' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
  t.is(result.confidence, 100)
})

test('perimeterx (body)', t => {
  const body = '<script>window._pxAppId = "PX123";</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'perimeterx')
  t.is(result.confidence, 90)
})

test('shapesecurity (header)', t => {
  const headers = { 'x-abc12345-a': 'test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'shapesecurity')
  t.is(result.confidence, 100)
})

test('shapesecurity (cookie)', t => {
  const headers = { cookie: 'shape123=data|1|0|test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'shapesecurity')
  t.is(result.confidence, 95)
})

test('kasada (header)', t => {
  const headers = { 'x-kasada': 'test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'kasada')
  t.is(result.confidence, 90)
})

test('kasada (cookie)', t => {
  const headers = { cookie: 'kas.js=test123' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'kasada')
  t.is(result.confidence, 95)
})

test('imperva (cookie)', t => {
  const headers = { cookie: 'visid_incap_12345=test' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
  t.is(result.confidence, 100)
})

test('imperva (header)', t => {
  const headers = { 'x-cdn': 'Incapsula' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
  t.is(result.confidence, 95)
})

test('recaptcha (url)', t => {
  const url = 'https://www.google.com/recaptcha/api.js'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
  t.is(result.confidence, 100)
})

test('recaptcha (body)', t => {
  const body = '<script>grecaptcha.execute();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'recaptcha')
  t.is(result.confidence, 100)
})

test('hcaptcha (url)', t => {
  const url = 'https://hcaptcha.com/captcha/v1'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
  t.is(result.confidence, 100)
})

test('hcaptcha (body)', t => {
  const body = '<div class="h-captcha"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'hcaptcha')
  t.is(result.confidence, 95)
})

test('funcaptcha (url)', t => {
  const url = 'https://client-api.arkoselabs.com/fc/gc/'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'funcaptcha')
  t.is(result.confidence, 100)
})

test('geetest (url)', t => {
  const url = 'https://api.geetest.com/ajax.php'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'geetest')
  t.is(result.confidence, 100)
})

test('cloudflare-turnstile (body)', t => {
  const body = '<div class="cf-turnstile"></div>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare-turnstile')
  t.is(result.confidence, 100)
})

test('aws-waf (cookie)', t => {
  const headers = { cookie: 'aws-waf-token=test123' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
  t.is(result.confidence, 100)
})

test('aws-waf (header)', t => {
  const headers = { 'x-amzn-waf-action': 'CHALLENGE' }
  const result = isAntibot({ headers })
  t.is(result.detected, true)
  t.is(result.provider, 'aws-waf')
  t.is(result.confidence, 90)
})

test('multiple detections', t => {
  const headers = { 'cf-mitigated': 'challenge' }
  const body = '<div class="g-recaptcha"></div>'
  const result = isAntibot({ headers, body })
  t.is(result.detected, true)
  t.is(result.provider, 'cloudflare')
  t.is(result.confidence, 100)
  t.truthy(result.detections)
  t.is(result.detections.length, 2)
  t.is(result.detections[0].name, 'cloudflare')
  t.is(result.detections[1].name, 'recaptcha')
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
