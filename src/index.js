'use strict'

const debug = require('debug-logfmt')('is-antibot')

const getHeader = (headers, name) =>
  typeof headers.get === 'function' ? headers.get(name) : headers[name]

const testPattern = (value, pattern, isRegex = false) => {
  if (!value) return false
  if (isRegex) {
    try {
      return new RegExp(pattern, 'i').test(value)
    } catch {
      return false
    }
  }
  return value.toLowerCase().includes(pattern.toLowerCase())
}

module.exports = ({ headers = {}, body = '', url = '' } = {}) => {
  // https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader(headers, 'cf-mitigated') === 'challenge') {
    debug({ detected: true, provider: 'cloudflare' })
    return { detected: true, provider: 'cloudflare' }
  }

  // https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (getHeader(headers, 'x-vercel-mitigated') === 'challenge') {
    debug({ detected: true, provider: 'vercel' })
    return { detected: true, provider: 'vercel' }
  }

  // https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (getHeader(headers, 'akamai-cache-status')?.startsWith('Error')) {
    debug({ detected: true, provider: 'akamai' })
    return { detected: true, provider: 'akamai' }
  }

  // Akamai - additional header detection
  if (
    getHeader(headers, 'akamai-grn') ||
    getHeader(headers, 'x-akamai-session-info')
  ) {
    debug({ detected: true, provider: 'akamai' })
    return { detected: true, provider: 'akamai' }
  }

  // https://docs.datadome.co/reference/validate-request
  // 1: Soft challenge / JS redirect / interstitial
  // 2: Hard challenge / HTML redirect / CAPTCHA
  if (['1', '2'].includes(getHeader(headers, 'x-dd-b'))) {
    debug({ detected: true, provider: 'datadome' })
    return { detected: true, provider: 'datadome' }
  }

  // DataDome - additional header detection
  if (getHeader(headers, 'x-datadome')) {
    debug({ detected: true, provider: 'datadome' })
    return { detected: true, provider: 'datadome' }
  }

  // PerimeterX
  if (getHeader(headers, 'x-px-authorization')) {
    debug({ detected: true, provider: 'perimeterx' })
    return { detected: true, provider: 'perimeterx' }
  }

  if (body && testPattern(body, 'window._pxAppId')) {
    debug({ detected: true, provider: 'perimeterx' })
    return { detected: true, provider: 'perimeterx' }
  }

  // Shape Security - dynamic header patterns: x-[8chars]-[abcdfz]
  const headerNames = Object.keys(headers)
  for (const name of headerNames) {
    if (/^x-[a-z0-9]{8}-[abcdfz]$/i.test(name)) {
      debug({ detected: true, provider: 'shapesecurity' })
      return { detected: true, provider: 'shapesecurity' }
    }
  }

  if (body && testPattern(body, 'shapesecurity')) {
    debug({ detected: true, provider: 'shapesecurity' })
    return { detected: true, provider: 'shapesecurity' }
  }

  // Kasada
  if (
    getHeader(headers, 'x-kasada') ||
    getHeader(headers, 'x-kasada-challenge')
  ) {
    debug({ detected: true, provider: 'kasada' })
    return { detected: true, provider: 'kasada' }
  }

  if (
    body &&
    (testPattern(body, '__kasada') || testPattern(body, 'kasada.js'))
  ) {
    debug({ detected: true, provider: 'kasada' })
    return { detected: true, provider: 'kasada' }
  }

  // Imperva/Incapsula
  if (
    getHeader(headers, 'x-cdn') === 'Incapsula' ||
    getHeader(headers, 'x-iinfo')
  ) {
    debug({ detected: true, provider: 'imperva' })
    return { detected: true, provider: 'imperva' }
  }

  if (
    body &&
    (testPattern(body, 'incapsula') || testPattern(body, 'imperva'))
  ) {
    debug({ detected: true, provider: 'imperva' })
    return { detected: true, provider: 'imperva' }
  }

  // reCAPTCHA
  if (
    url &&
    (testPattern(url, 'recaptcha/api') ||
      testPattern(url, 'google\\.com/recaptcha', true))
  ) {
    debug({ detected: true, provider: 'recaptcha' })
    return { detected: true, provider: 'recaptcha' }
  }

  if (body && testPattern(body, 'grecaptcha')) {
    debug({ detected: true, provider: 'recaptcha' })
    return { detected: true, provider: 'recaptcha' }
  }

  if (body && testPattern(body, 'g-recaptcha')) {
    debug({ detected: true, provider: 'recaptcha' })
    return { detected: true, provider: 'recaptcha' }
  }

  // hCaptcha
  if (url && testPattern(url, 'hcaptcha\\.com', true)) {
    debug({ detected: true, provider: 'hcaptcha' })
    return { detected: true, provider: 'hcaptcha' }
  }

  if (body && testPattern(body, 'hcaptcha')) {
    debug({ detected: true, provider: 'hcaptcha' })
    return { detected: true, provider: 'hcaptcha' }
  }

  if (body && testPattern(body, 'h-captcha')) {
    debug({ detected: true, provider: 'hcaptcha' })
    return { detected: true, provider: 'hcaptcha' }
  }

  // FunCaptcha (Arkose Labs)
  if (
    url &&
    (testPattern(url, 'arkoselabs\\.com', true) ||
      testPattern(url, 'funcaptcha'))
  ) {
    debug({ detected: true, provider: 'funcaptcha' })
    return { detected: true, provider: 'funcaptcha' }
  }

  if (
    body &&
    (testPattern(body, 'funcaptcha') || testPattern(body, 'arkose'))
  ) {
    debug({ detected: true, provider: 'funcaptcha' })
    return { detected: true, provider: 'funcaptcha' }
  }

  // GeeTest
  if (url && testPattern(url, 'geetest\\.com', true)) {
    debug({ detected: true, provider: 'geetest' })
    return { detected: true, provider: 'geetest' }
  }

  if (body && testPattern(body, 'geetest')) {
    debug({ detected: true, provider: 'geetest' })
    return { detected: true, provider: 'geetest' }
  }

  if (body && testPattern(body, 'gt.js')) {
    debug({ detected: true, provider: 'geetest' })
    return { detected: true, provider: 'geetest' }
  }

  // Cloudflare Turnstile
  if (
    url &&
    testPattern(url, 'challenges\\.cloudflare\\.com/turnstile', true)
  ) {
    debug({ detected: true, provider: 'cloudflare-turnstile' })
    return { detected: true, provider: 'cloudflare-turnstile' }
  }

  if (body && testPattern(body, 'cf-turnstile')) {
    debug({ detected: true, provider: 'cloudflare-turnstile' })
    return { detected: true, provider: 'cloudflare-turnstile' }
  }

  if (body && testPattern(body, 'turnstile')) {
    debug({ detected: true, provider: 'cloudflare-turnstile' })
    return { detected: true, provider: 'cloudflare-turnstile' }
  }

  // AWS WAF
  if (
    getHeader(headers, 'x-amzn-waf-action') ||
    getHeader(headers, 'x-amzn-requestid')
  ) {
    debug({ detected: true, provider: 'aws-waf' })
    return { detected: true, provider: 'aws-waf' }
  }

  if (body && testPattern(body, 'aws-waf')) {
    debug({ detected: true, provider: 'aws-waf' })
    return { detected: true, provider: 'aws-waf' }
  }

  debug({ detected: false, provider: null })
  return { detected: false, provider: null }
}

module.exports.debug = debug
