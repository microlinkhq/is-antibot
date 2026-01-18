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

const createResult = (detected, provider) => {
  debug({ detected, provider })
  return { detected, provider }
}

module.exports = ({ headers = {}, body = '', url = '' } = {}) => {
  // https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader(headers, 'cf-mitigated') === 'challenge') {
    return createResult(true, 'cloudflare')
  }

  // https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (getHeader(headers, 'x-vercel-mitigated') === 'challenge') {
    return createResult(true, 'vercel')
  }

  // https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (getHeader(headers, 'akamai-cache-status')?.startsWith('Error')) {
    return createResult(true, 'akamai')
  }

  // Akamai - additional header detection
  if (
    getHeader(headers, 'akamai-grn') ||
    getHeader(headers, 'x-akamai-session-info')
  ) {
    return createResult(true, 'akamai')
  }

  // https://docs.datadome.co/reference/validate-request
  // 1: Soft challenge / JS redirect / interstitial
  // 2: Hard challenge / HTML redirect / CAPTCHA
  if (['1', '2'].includes(getHeader(headers, 'x-dd-b'))) {
    return createResult(true, 'datadome')
  }

  // DataDome - additional header detection
  if (getHeader(headers, 'x-datadome')) {
    return createResult(true, 'datadome')
  }

  // PerimeterX
  if (getHeader(headers, 'x-px-authorization')) {
    return createResult(true, 'perimeterx')
  }

  if (body && testPattern(body, 'window._pxAppId')) {
    return createResult(true, 'perimeterx')
  }

  // Shape Security - dynamic header patterns: x-[8chars]-[abcdfz]
  const headerNames = Object.keys(headers)
  for (const name of headerNames) {
    if (/^x-[a-z0-9]{8}-[abcdfz]$/i.test(name)) {
      return createResult(true, 'shapesecurity')
    }
  }

  if (body && testPattern(body, 'shapesecurity')) {
    return createResult(true, 'shapesecurity')
  }

  // Kasada
  if (
    getHeader(headers, 'x-kasada') ||
    getHeader(headers, 'x-kasada-challenge')
  ) {
    return createResult(true, 'kasada')
  }

  if (
    body &&
    (testPattern(body, '__kasada') || testPattern(body, 'kasada.js'))
  ) {
    return createResult(true, 'kasada')
  }

  // Imperva/Incapsula
  if (
    getHeader(headers, 'x-cdn') === 'Incapsula' ||
    getHeader(headers, 'x-iinfo')
  ) {
    return createResult(true, 'imperva')
  }

  if (
    body &&
    (testPattern(body, 'incapsula') || testPattern(body, 'imperva'))
  ) {
    return createResult(true, 'imperva')
  }

  // reCAPTCHA
  if (
    url &&
    (testPattern(url, 'recaptcha/api') ||
      testPattern(url, 'google\\.com/recaptcha', true))
  ) {
    return createResult(true, 'recaptcha')
  }

  if (body && testPattern(body, 'grecaptcha')) {
    return createResult(true, 'recaptcha')
  }

  if (body && testPattern(body, 'g-recaptcha')) {
    return createResult(true, 'recaptcha')
  }

  // hCaptcha
  if (url && testPattern(url, 'hcaptcha\\.com', true)) {
    return createResult(true, 'hcaptcha')
  }

  if (body && testPattern(body, 'hcaptcha')) {
    return createResult(true, 'hcaptcha')
  }

  if (body && testPattern(body, 'h-captcha')) {
    return createResult(true, 'hcaptcha')
  }

  // FunCaptcha (Arkose Labs)
  if (
    url &&
    (testPattern(url, 'arkoselabs\\.com', true) ||
      testPattern(url, 'funcaptcha'))
  ) {
    return createResult(true, 'funcaptcha')
  }

  if (
    body &&
    (testPattern(body, 'funcaptcha') || testPattern(body, 'arkose'))
  ) {
    return createResult(true, 'funcaptcha')
  }

  // GeeTest
  if (url && testPattern(url, 'geetest\\.com', true)) {
    return createResult(true, 'geetest')
  }

  if (body && testPattern(body, 'geetest')) {
    return createResult(true, 'geetest')
  }

  if (body && testPattern(body, 'gt.js')) {
    return createResult(true, 'geetest')
  }

  // Cloudflare Turnstile
  if (
    url &&
    testPattern(url, 'challenges\\.cloudflare\\.com/turnstile', true)
  ) {
    return createResult(true, 'cloudflare-turnstile')
  }

  if (body && testPattern(body, 'cf-turnstile')) {
    return createResult(true, 'cloudflare-turnstile')
  }

  if (body && testPattern(body, 'turnstile')) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // AWS WAF
  if (
    getHeader(headers, 'x-amzn-waf-action') ||
    getHeader(headers, 'x-amzn-requestid')
  ) {
    return createResult(true, 'aws-waf')
  }

  if (body && testPattern(body, 'aws-waf')) {
    return createResult(true, 'aws-waf')
  }

  return createResult(false, null)
}

module.exports.debug = debug
