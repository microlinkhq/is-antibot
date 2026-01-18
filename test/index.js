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

test('imperva (body)', t => {
  const body = '<script>incapsula.init();</script>'
  const result = isAntibot({ body })
  t.is(result.detected, true)
  t.is(result.provider, 'imperva')
})

test('recaptcha (url)', t => {
  const url = 'https://www.google.com/recaptcha/api.js'
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

test('funcaptcha (url)', t => {
  const url = 'https://client-api.arkoselabs.com/fc/gc/'
  const result = isAntibot({ url })
  t.is(result.detected, true)
  t.is(result.provider, 'funcaptcha')
})

test('funcaptcha (body)', t => {
  const body = '<script>funcaptcha.init();</script>'
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
