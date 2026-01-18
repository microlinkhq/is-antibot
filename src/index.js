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
  // CloudFlare: Check for cf-mitigated header with 'challenge' value
  // Official docs: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader(headers, 'cf-mitigated') === 'challenge') {
    return createResult(true, 'cloudflare')
  }

  // Vercel: Check for x-vercel-mitigated header with 'challenge' value
  // Solver reference: https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (getHeader(headers, 'x-vercel-mitigated') === 'challenge') {
    return createResult(true, 'vercel')
  }

  // Akamai: Check for akamai-cache-status header starting with 'Error'
  // Official docs: https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (getHeader(headers, 'akamai-cache-status')?.startsWith('Error')) {
    return createResult(true, 'akamai')
  }

  // Akamai: Check for additional identifying headers (akamai-grn, x-akamai-session-info)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/akamai.json
  if (
    getHeader(headers, 'akamai-grn') ||
    getHeader(headers, 'x-akamai-session-info')
  ) {
    return createResult(true, 'akamai')
  }

  // DataDome: Check for x-dd-b header with values '1' (soft challenge) or '2' (hard challenge/CAPTCHA)
  // Official docs: https://docs.datadome.co/reference/validate-request
  // 1: Soft challenge / JS redirect / interstitial
  // 2: Hard challenge / HTML redirect / CAPTCHA
  if (['1', '2'].includes(getHeader(headers, 'x-dd-b'))) {
    return createResult(true, 'datadome')
  }

  // DataDome: Check for x-datadome header presence
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/datadome.json
  if (getHeader(headers, 'x-datadome')) {
    return createResult(true, 'datadome')
  }

  // PerimeterX: Check for X-PX-Authorization header (primary indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/perimeterx.json#L71-L84
  if (getHeader(headers, 'x-px-authorization')) {
    return createResult(true, 'perimeterx')
  }

  // PerimeterX: Check for window._pxAppId in body (JavaScript initialization)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/perimeterx.json#L130-L137
  if (body && testPattern(body, 'window._pxAppId')) {
    return createResult(true, 'perimeterx')
  }

  // Shape Security: Check for dynamic header patterns x-[8chars]-[abcdfz]
  // These headers use 8 random characters followed by suffixes like -a, -b, -c, -d, -f, or -z
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/shapesecurity.json#L30-L113
  const headerNames = Object.keys(headers)
  for (const name of headerNames) {
    if (/^x-[a-z0-9]{8}-[abcdfz]$/i.test(name)) {
      return createResult(true, 'shapesecurity')
    }
  }

  // Shape Security: Check for 'shapesecurity' text in response body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/shapesecurity.json#L136-L142
  if (body && testPattern(body, 'shapesecurity')) {
    return createResult(true, 'shapesecurity')
  }

  // Kasada: Check for x-kasada or x-kasada-challenge headers
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/kasada.json#L57-L85
  if (
    getHeader(headers, 'x-kasada') ||
    getHeader(headers, 'x-kasada-challenge')
  ) {
    return createResult(true, 'kasada')
  }

  // Kasada: Check for __kasada global object or kasada.js script in body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/kasada.json#L117-L144
  if (
    body &&
    (testPattern(body, '__kasada') || testPattern(body, 'kasada.js'))
  ) {
    return createResult(true, 'kasada')
  }

  // Imperva/Incapsula: Check for x-cdn header with 'Incapsula' value or x-iinfo header
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/incapsula.json#L86-L109
  if (
    getHeader(headers, 'x-cdn') === 'Incapsula' ||
    getHeader(headers, 'x-iinfo')
  ) {
    return createResult(true, 'imperva')
  }

  // Imperva/Incapsula: Check for 'incapsula' or 'imperva' text in response body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/incapsula.json#L111-L124
  if (
    body &&
    (testPattern(body, 'incapsula') || testPattern(body, 'imperva'))
  ) {
    return createResult(true, 'imperva')
  }

  // reCAPTCHA: Check for recaptcha/api or google.com/recaptcha in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L13-L48
  if (
    url &&
    (testPattern(url, 'recaptcha/api') ||
      testPattern(url, 'google\\.com/recaptcha', true))
  ) {
    return createResult(true, 'recaptcha')
  }

  // reCAPTCHA: Check for grecaptcha global object in body (primary JavaScript indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L51-L58
  if (body && testPattern(body, 'grecaptcha')) {
    return createResult(true, 'recaptcha')
  }

  // reCAPTCHA: Check for g-recaptcha container class in body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L66-L73
  if (body && testPattern(body, 'g-recaptcha')) {
    return createResult(true, 'recaptcha')
  }

  // hCaptcha: Check for hcaptcha.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L13-L22
  if (url && testPattern(url, 'hcaptcha\\.com', true)) {
    return createResult(true, 'hcaptcha')
  }

  // hCaptcha: Check for hcaptcha object in body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L42-L50
  if (body && testPattern(body, 'hcaptcha')) {
    return createResult(true, 'hcaptcha')
  }

  // hCaptcha: Check for h-captcha container class in body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L51-L58
  if (body && testPattern(body, 'h-captcha')) {
    return createResult(true, 'hcaptcha')
  }

  // FunCaptcha (Arkose Labs): Check for arkoselabs.com or funcaptcha in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/funcaptcha.json#L13-L40
  if (
    url &&
    (testPattern(url, 'arkoselabs\\.com', true) ||
      testPattern(url, 'funcaptcha'))
  ) {
    return createResult(true, 'funcaptcha')
  }

  // FunCaptcha (Arkose Labs): Check for funcaptcha or arkose text in body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/funcaptcha.json#L42-L55
  if (
    body &&
    (testPattern(body, 'funcaptcha') || testPattern(body, 'arkose'))
  ) {
    return createResult(true, 'funcaptcha')
  }

  // GeeTest: Check for geetest.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L13-L43
  if (url && testPattern(url, 'geetest\\.com', true)) {
    return createResult(true, 'geetest')
  }

  // GeeTest: Check for geetest object or text in body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L45-L52
  if (body && testPattern(body, 'geetest')) {
    return createResult(true, 'geetest')
  }

  // GeeTest: Check for gt.js script in body
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L53-L60
  if (body && testPattern(body, 'gt.js')) {
    return createResult(true, 'geetest')
  }

  // Cloudflare Turnstile: Check for challenges.cloudflare.com/turnstile in URL
  // Turnstile is Cloudflare's CAPTCHA alternative with privacy focus
  if (
    url &&
    testPattern(url, 'challenges\\.cloudflare\\.com/turnstile', true)
  ) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for cf-turnstile class in body (primary indicator)
  if (body && testPattern(body, 'cf-turnstile')) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for turnstile text in body (secondary indicator)
  if (body && testPattern(body, 'turnstile')) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // AWS WAF: Check for x-amzn-waf-action or x-amzn-requestid headers
  // These headers are set by AWS WAF when bot control rules are triggered
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/aws-waf.json
  if (
    getHeader(headers, 'x-amzn-waf-action') ||
    getHeader(headers, 'x-amzn-requestid')
  ) {
    return createResult(true, 'aws-waf')
  }

  // AWS WAF: Check for aws-waf text in body (challenge page indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/aws-waf.json#L47-L73
  if (body && testPattern(body, 'aws-waf')) {
    return createResult(true, 'aws-waf')
  }

  return createResult(false, null)
}

module.exports.debug = debug
module.exports.testPattern = testPattern
