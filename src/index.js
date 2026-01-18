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
  let detected = false
  let provider = null

  // https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader(headers, 'cf-mitigated') === 'challenge') {
    detected = true
    provider = 'cloudflare'
  }

  // https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (!detected && getHeader(headers, 'x-vercel-mitigated') === 'challenge') {
    detected = true
    provider = 'vercel'
  }

  // https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (
    !detected &&
    getHeader(headers, 'akamai-cache-status')?.startsWith('Error')
  ) {
    detected = true
    provider = 'akamai'
  }

  // Akamai - additional header detection
  if (
    !detected &&
    (getHeader(headers, 'akamai-grn') ||
      getHeader(headers, 'x-akamai-session-info'))
  ) {
    detected = true
    provider = 'akamai'
  }

  // https://docs.datadome.co/reference/validate-request
  // 1: Soft challenge / JS redirect / interstitial
  // 2: Hard challenge / HTML redirect / CAPTCHA
  if (!detected && ['1', '2'].includes(getHeader(headers, 'x-dd-b'))) {
    detected = true
    provider = 'datadome'
  }

  // DataDome - additional header detection
  if (!detected && getHeader(headers, 'x-datadome')) {
    detected = true
    provider = 'datadome'
  }

  // PerimeterX
  if (!detected && getHeader(headers, 'x-px-authorization')) {
    detected = true
    provider = 'perimeterx'
  }

  if (!detected && body && testPattern(body, 'window._pxAppId')) {
    detected = true
    provider = 'perimeterx'
  }

  // Shape Security - dynamic header patterns: x-[8chars]-[abcdfz]
  if (!detected) {
    const headerNames = Object.keys(headers)
    for (const name of headerNames) {
      if (/^x-[a-z0-9]{8}-[abcdfz]$/i.test(name)) {
        detected = true
        provider = 'shapesecurity'
        break
      }
    }
  }

  if (!detected && body && testPattern(body, 'shapesecurity')) {
    detected = true
    provider = 'shapesecurity'
  }

  // Kasada
  if (
    !detected &&
    (getHeader(headers, 'x-kasada') || getHeader(headers, 'x-kasada-challenge'))
  ) {
    detected = true
    provider = 'kasada'
  }

  if (
    !detected &&
    body &&
    (testPattern(body, '__kasada') || testPattern(body, 'kasada.js'))
  ) {
    detected = true
    provider = 'kasada'
  }

  // Imperva/Incapsula
  if (
    !detected &&
    (getHeader(headers, 'x-cdn') === 'Incapsula' ||
      getHeader(headers, 'x-iinfo'))
  ) {
    detected = true
    provider = 'imperva'
  }

  if (
    !detected &&
    body &&
    (testPattern(body, 'incapsula') || testPattern(body, 'imperva'))
  ) {
    detected = true
    provider = 'imperva'
  }

  // reCAPTCHA
  if (
    !detected &&
    url &&
    (testPattern(url, 'recaptcha/api') ||
      testPattern(url, 'google\\.com/recaptcha', true))
  ) {
    detected = true
    provider = 'recaptcha'
  }

  if (!detected && body && testPattern(body, 'grecaptcha')) {
    detected = true
    provider = 'recaptcha'
  }

  if (!detected && body && testPattern(body, 'g-recaptcha')) {
    detected = true
    provider = 'recaptcha'
  }

  // hCaptcha
  if (!detected && url && testPattern(url, 'hcaptcha\\.com', true)) {
    detected = true
    provider = 'hcaptcha'
  }

  if (!detected && body && testPattern(body, 'hcaptcha')) {
    detected = true
    provider = 'hcaptcha'
  }

  if (!detected && body && testPattern(body, 'h-captcha')) {
    detected = true
    provider = 'hcaptcha'
  }

  // FunCaptcha (Arkose Labs)
  if (
    !detected &&
    url &&
    (testPattern(url, 'arkoselabs\\.com', true) ||
      testPattern(url, 'funcaptcha'))
  ) {
    detected = true
    provider = 'funcaptcha'
  }

  if (
    !detected &&
    body &&
    (testPattern(body, 'funcaptcha') || testPattern(body, 'arkose'))
  ) {
    detected = true
    provider = 'funcaptcha'
  }

  // GeeTest
  if (!detected && url && testPattern(url, 'geetest\\.com', true)) {
    detected = true
    provider = 'geetest'
  }

  if (!detected && body && testPattern(body, 'geetest')) {
    detected = true
    provider = 'geetest'
  }

  if (!detected && body && testPattern(body, 'gt.js')) {
    detected = true
    provider = 'geetest'
  }

  // Cloudflare Turnstile
  if (
    !detected &&
    url &&
    testPattern(url, 'challenges\\.cloudflare\\.com/turnstile', true)
  ) {
    detected = true
    provider = 'cloudflare-turnstile'
  }

  if (!detected && body && testPattern(body, 'cf-turnstile')) {
    detected = true
    provider = 'cloudflare-turnstile'
  }

  if (!detected && body && testPattern(body, 'turnstile')) {
    detected = true
    provider = 'cloudflare-turnstile'
  }

  // AWS WAF
  if (
    !detected &&
    (getHeader(headers, 'x-amzn-waf-action') ||
      getHeader(headers, 'x-amzn-requestid'))
  ) {
    detected = true
    provider = 'aws-waf'
  }

  if (!detected && body && testPattern(body, 'aws-waf')) {
    detected = true
    provider = 'aws-waf'
  }

  debug({ detected, provider })
  return { detected, provider }
}

module.exports.debug = debug
