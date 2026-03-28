'use strict'

const { splitSetCookieString } = require('cookie-es')
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

const testSetCookie = (headers, pattern) => {
  const cookiesString = getHeader(headers, 'set-cookie')
  return splitSetCookieString(cookiesString).some(c => c.startsWith(pattern))
}

const detect = ({ headers = {}, html = '', url = '' } = {}) => {
  // CloudFlare: Check for cf-mitigated header with 'challenge' value
  // Official docs: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader(headers, 'cf-mitigated') === 'challenge') {
    return createResult(true, 'cloudflare')
  }

  // Cloudflare: cf_clearance cookie indicates Cloudflare challenge flow
  if (testSetCookie(headers, 'cf_clearance=')) {
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

  // Akamai: _abck bot manager tracking cookie
  if (testSetCookie(headers, '_abck=')) {
    return createResult(true, 'akamai')
  }

  // Akamai: Bot Manager API namespace (bmak) in html
  if (html && testPattern(html, 'bmak.')) {
    return createResult(true, 'akamai')
  }

  // DataDome: Check for x-dd-b header with values '1' (soft challenge) or '2' (hard challenge/CAPTCHA)
  // Official docs: https://docs.datadome.co/reference/validate-request
  if (['1', '2'].includes(getHeader(headers, 'x-dd-b'))) {
    return createResult(true, 'datadome')
  }

  // DataDome: Check for x-datadome or x-datadome-cid header presence
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/datadome.json
  if (
    getHeader(headers, 'x-datadome') ||
    getHeader(headers, 'x-datadome-cid')
  ) {
    return createResult(true, 'datadome')
  }

  // DataDome: datadome tracking cookie
  if (testSetCookie(headers, 'datadome=')) {
    return createResult(true, 'datadome')
  }

  // PerimeterX: Check for X-PX-Authorization header (primary indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/perimeterx.json#L71-L84
  if (getHeader(headers, 'x-px-authorization')) {
    return createResult(true, 'perimeterx')
  }

  // PerimeterX: Check for window._pxAppId, pxInit, or _pxAction in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/perimeterx.json#L130-L137
  if (
    html &&
    (testPattern(html, 'window._pxAppId') ||
      testPattern(html, 'pxInit') ||
      testPattern(html, '_pxAction'))
  ) {
    return createResult(true, 'perimeterx')
  }

  // PerimeterX: _px3 or _pxhd cookies
  if (testSetCookie(headers, '_px3=') || testSetCookie(headers, '_pxhd=')) {
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

  // Shape Security: Check for 'shapesecurity' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/shapesecurity.json#L136-L142
  if (html && testPattern(html, 'shapesecurity')) {
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

  // Kasada: Check for __kasada global object or kasada.js script in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/kasada.json#L117-L144
  if (
    html &&
    (testPattern(html, '__kasada') || testPattern(html, 'kasada.js'))
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

  // Imperva/Incapsula: Check for 'incapsula' or 'imperva' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/incapsula.json#L111-L124
  if (
    html &&
    (testPattern(html, 'incapsula') || testPattern(html, 'imperva'))
  ) {
    return createResult(true, 'imperva')
  }

  // Imperva/Incapsula: incap_ses_, visid_incap_, or reese84 cookies
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/incapsula.json
  if (
    testSetCookie(headers, 'incap_ses_') ||
    testSetCookie(headers, 'visid_incap_') ||
    testSetCookie(headers, 'reese84=')
  ) {
    return createResult(true, 'imperva')
  }

  // Reblaze: rbzid or rbzsessionid cookies
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/reblaze.json
  if (
    testSetCookie(headers, 'rbzid=') ||
    testSetCookie(headers, 'rbzsessionid=')
  ) {
    return createResult(true, 'reblaze')
  }

  // Reblaze: Check for 'reblaze' text in response html
  if (html && testPattern(html, 'reblaze')) {
    return createResult(true, 'reblaze')
  }

  // Cheq: Check for CheqSdk or cheqzone.com in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/cheq.json
  if (
    html &&
    (testPattern(html, 'CheqSdk') || testPattern(html, 'cheqzone.com'))
  ) {
    return createResult(true, 'cheq')
  }

  // Cheq: Check for cheqzone.com or cheq.ai in URL
  if (
    url &&
    (testPattern(url, 'cheqzone\\.com', true) ||
      testPattern(url, 'cheq\\.ai', true))
  ) {
    return createResult(true, 'cheq')
  }

  // Sucuri: Check for 'sucuri' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/sucuri.json
  if (html && testPattern(html, 'sucuri')) {
    return createResult(true, 'sucuri')
  }

  // ThreatMetrix: Check for 'ThreatMetrix' in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/threatmetrix.json
  if (html && testPattern(html, 'ThreatMetrix')) {
    return createResult(true, 'threatmetrix')
  }

  // ThreatMetrix: Check for fp/check.js fingerprint endpoint in URL
  if (url && testPattern(url, 'fp/check.js')) {
    return createResult(true, 'threatmetrix')
  }

  // Meetrics: Check for 'meetrics' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/meetrics.json
  if (html && testPattern(html, 'meetrics')) {
    return createResult(true, 'meetrics')
  }

  // Meetrics: Check for meetrics.com in URL
  if (url && testPattern(url, 'meetrics\\.com', true)) {
    return createResult(true, 'meetrics')
  }

  // Ocule: Check for ocule.co.uk in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/ocule.json
  if (html && testPattern(html, 'ocule.co.uk')) {
    return createResult(true, 'ocule')
  }

  // Ocule: Check for ocule.co.uk in URL
  if (url && testPattern(url, 'ocule\\.co\\.uk', true)) {
    return createResult(true, 'ocule')
  }

  // reCAPTCHA: Check for recaptcha/api, google.com/recaptcha, gstatic.com/recaptcha, or recaptcha.net in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L13-L48
  if (
    url &&
    (testPattern(url, 'recaptcha/api') ||
      testPattern(url, 'google\\.com/recaptcha', true) ||
      testPattern(url, 'gstatic.com/recaptcha') ||
      testPattern(url, 'recaptcha.net'))
  ) {
    return createResult(true, 'recaptcha')
  }

  // reCAPTCHA: Check for grecaptcha global object in html (primary JavaScript indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L51-L58
  if (html && testPattern(html, 'grecaptcha')) {
    return createResult(true, 'recaptcha')
  }

  // reCAPTCHA: Check for g-recaptcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L66-L73
  if (html && testPattern(html, 'g-recaptcha')) {
    return createResult(true, 'recaptcha')
  }

  // hCaptcha: Check for hcaptcha.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L13-L22
  if (url && testPattern(url, 'hcaptcha\\.com', true)) {
    return createResult(true, 'hcaptcha')
  }

  // hCaptcha: Check for hcaptcha object in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L42-L50
  if (html && testPattern(html, 'hcaptcha')) {
    return createResult(true, 'hcaptcha')
  }

  // hCaptcha: Check for h-captcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L51-L58
  if (html && testPattern(html, 'h-captcha')) {
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

  // FunCaptcha (Arkose Labs): Check for funcaptcha or arkose text in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/funcaptcha.json#L42-L55
  if (
    html &&
    (testPattern(html, 'funcaptcha') || testPattern(html, 'arkose'))
  ) {
    return createResult(true, 'funcaptcha')
  }

  // GeeTest: Check for geetest.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L13-L43
  if (url && testPattern(url, 'geetest\\.com', true)) {
    return createResult(true, 'geetest')
  }

  // GeeTest: Check for geetest object or text in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L45-L52
  if (html && testPattern(html, 'geetest')) {
    return createResult(true, 'geetest')
  }

  // GeeTest: Check for gt.js script in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L53-L60
  if (html && testPattern(html, 'gt.js')) {
    return createResult(true, 'geetest')
  }

  // Cloudflare Turnstile: Check for challenges.cloudflare.com/turnstile in URL
  if (
    url &&
    testPattern(url, 'challenges\\.cloudflare\\.com/turnstile', true)
  ) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for cf-turnstile class in html
  if (html && testPattern(html, 'cf-turnstile')) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for turnstile text in html
  if (html && testPattern(html, 'turnstile')) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // Friendly Captcha: Check for friendlycaptcha.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/friendlycaptcha.json
  if (url && testPattern(url, 'friendlycaptcha\\.com', true)) {
    return createResult(true, 'friendly-captcha')
  }

  // Friendly Captcha: Check for frc-captcha container or friendlyChallenge object in html
  if (
    html &&
    (testPattern(html, 'frc-captcha') || testPattern(html, 'friendlyChallenge'))
  ) {
    return createResult(true, 'friendly-captcha')
  }

  // Captcha.eu: Check for captcha.eu in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/captchaeu.json
  if (url && testPattern(url, 'captcha\\.eu', true)) {
    return createResult(true, 'captcha-eu')
  }

  // Captcha.eu: Check for CaptchaEU or captchaeu in html
  if (
    html &&
    (testPattern(html, 'CaptchaEU') || testPattern(html, 'captchaeu'))
  ) {
    return createResult(true, 'captcha-eu')
  }

  // QCloud Captcha (Tencent): Check for turing.captcha.qcloud.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/qcloud.json
  if (url && testPattern(url, 'turing\\.captcha\\.qcloud\\.com', true)) {
    return createResult(true, 'qcloud-captcha')
  }

  // QCloud Captcha: Check for TencentCaptcha or turing.captcha in html
  if (
    html &&
    (testPattern(html, 'TencentCaptcha') || testPattern(html, 'turing.captcha'))
  ) {
    return createResult(true, 'qcloud-captcha')
  }

  // AliExpress CAPTCHA: Check for punish?x5secdata in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/aliexpress.json
  if (url && testPattern(url, 'punish\\?x5secdata', true)) {
    return createResult(true, 'aliexpress-captcha')
  }

  // AliExpress CAPTCHA: Check for x5secdata in html
  if (html && testPattern(html, 'x5secdata')) {
    return createResult(true, 'aliexpress-captcha')
  }

  // LinkedIn: trkCode=bf cookie ("bot filter") is set when LinkedIn blocks a request
  if (testSetCookie(headers, 'trkCode=bf')) {
    return createResult(true, 'linkedin')
  }

  // YouTube: empty title pattern indicates a degraded response requiring BotGuard JS attestation
  // Normal pages have `<title>Video Title - YouTube</title>`, bots get `<title> - YouTube</title>`
  if (html && testPattern(html, '<title>\\s*-\\s*YouTube<\\/title>', true)) {
    return createResult(true, 'youtube')
  }

  // AWS WAF: Check for x-amzn-waf-action or x-amzn-requestid headers
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/aws-waf.json
  if (
    getHeader(headers, 'x-amzn-waf-action') ||
    getHeader(headers, 'x-amzn-requestid')
  ) {
    return createResult(true, 'aws-waf')
  }

  // AWS WAF: Check for aws-waf or awswaf text in html
  if (html && (testPattern(html, 'aws-waf') || testPattern(html, 'awswaf'))) {
    return createResult(true, 'aws-waf')
  }

  // AWS WAF: aws-waf-token cookie
  if (testSetCookie(headers, 'aws-waf-token=')) {
    return createResult(true, 'aws-waf')
  }

  return createResult(false, null)
}

const isAntibot = (input = {}) => {
  // Response-like object (e.g., Fetch Response): clone to keep the original body unconsumed
  if (typeof input.text === 'function') {
    return input
      .clone()
      .text()
      .then(html => detect({ headers: input.headers, html, url: input.url }))
  }
  // Plain object: use `html` directly, or fall back to `body` if it's a string (e.g., got response)
  const { headers, html, body, url } = input
  return detect({ headers, html: html || body, url })
}

module.exports = isAntibot
module.exports.debug = debug
module.exports.testPattern = testPattern
module.exports.testSetCookie = testSetCookie
