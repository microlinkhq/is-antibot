'use strict'

const { splitSetCookieString } = require('cookie-es')
const debug = require('debug-logfmt')('is-antibot')

const DETECTION = {
  HEADERS: 'headers',
  COOKIES: 'cookies',
  HTML: 'html',
  URL: 'url'
}

const createGetHeader = headers =>
  typeof headers.get === 'function'
    ? name => headers.get(name)
    : name => headers[name]

const createTestPattern = value => {
  if (!value) return () => false
  const lowerValue = value.toLowerCase()
  return (pattern, isRegex = false) => {
    if (isRegex) {
      try {
        return new RegExp(pattern, 'i').test(value)
      } catch {
        return false
      }
    }
    return lowerValue.includes(pattern.toLowerCase())
  }
}

const createResult = (detected, provider, detection = null) => {
  debug({ detected, provider, detection })
  return { detected, provider, detection }
}

const createHasCookie = headers => {
  const getHeader = createGetHeader(headers)
  return pattern =>
    splitSetCookieString(getHeader('set-cookie')).some(c =>
      c.startsWith(pattern)
    )
}

const getHeaderNames = headers =>
  typeof headers.keys === 'function'
    ? Array.from(headers.keys())
    : Object.keys(headers)

const detect = ({ headers = {}, html = '', url = '' } = {}) => {
  const getHeader = createGetHeader(headers)
  const hasCookie = createHasCookie(headers)
  const htmlHas = createTestPattern(html)
  const urlHas = createTestPattern(url)

  const hasAnyHeader = headerNames =>
    headerNames.some(headerName => getHeader(headerName))

  const hasAnyCookie = cookieNames =>
    cookieNames.some(cookieName => hasCookie(cookieName))

  const hasAnyHtml = patterns => patterns.some(pattern => htmlHas(pattern))

  const hasAnyUrl = (...patterns) => patterns.some(pattern => urlHas(pattern))

  const hasAnyUrlRegex = (...patterns) =>
    patterns.some(pattern => urlHas(pattern, true))

  const byHeaders = provider => createResult(true, provider, DETECTION.HEADERS)

  const byCookies = provider => createResult(true, provider, DETECTION.COOKIES)

  const byHtml = provider => createResult(true, provider, DETECTION.HTML)

  const byUrl = provider => createResult(true, provider, DETECTION.URL)

  // CloudFlare: Check for cf-mitigated header with 'challenge' value
  // Official docs: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader('cf-mitigated') === 'challenge') {
    return byHeaders('cloudflare')
  }

  // Cloudflare: cf_clearance cookie indicates Cloudflare challenge flow
  if (hasCookie('cf_clearance=')) {
    return byCookies('cloudflare')
  }

  // Vercel: Check for x-vercel-mitigated header with 'challenge' value
  // Solver reference: https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (getHeader('x-vercel-mitigated') === 'challenge') {
    return byHeaders('vercel')
  }

  // Akamai: Check for akamai-cache-status header starting with 'Error'
  // Official docs: https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (getHeader('akamai-cache-status')?.startsWith('Error')) {
    return byHeaders('akamai')
  }

  // Akamai: Check for additional identifying headers (akamai-grn, x-akamai-session-info)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-akamai.json
  if (hasAnyHeader(['akamai-grn', 'x-akamai-session-info'])) {
    return byHeaders('akamai')
  }

  // Akamai: _abck bot manager tracking cookie
  if (hasCookie('_abck=')) {
    return byCookies('akamai')
  }

  // Akamai: Bot Manager API namespace (bmak) in html
  if (htmlHas('bmak.')) {
    return byHtml('akamai')
  }

  // DataDome: Check for x-dd-b header with values '1' (soft challenge) or '2' (hard challenge/CAPTCHA)
  // Official docs: https://docs.datadome.co/reference/validate-request
  if (['1', '2'].includes(getHeader('x-dd-b'))) {
    return byHeaders('datadome')
  }

  // DataDome: Check for x-datadome or x-datadome-cid header presence
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-datadome.json
  if (hasAnyHeader(['x-datadome', 'x-datadome-cid'])) {
    return byHeaders('datadome')
  }

  // DataDome: datadome tracking cookie
  if (hasCookie('datadome=')) {
    return byCookies('datadome')
  }

  // PerimeterX: Check for X-PX-Authorization header (primary indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-perimeterx.json
  if (getHeader('x-px-authorization')) {
    return byHeaders('perimeterx')
  }

  // PerimeterX: Check for window._pxAppId, pxInit, or _pxAction in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-perimeterx.json
  if (hasAnyHtml(['window._pxAppId', 'pxInit', '_pxAction'])) {
    return byHtml('perimeterx')
  }

  // PerimeterX: _px3 or _pxhd cookies
  if (hasAnyCookie(['_px3=', '_pxhd='])) {
    return byCookies('perimeterx')
  }

  // Shape Security: Check for dynamic header patterns x-[8chars]-[abcdfz]
  // These headers use 8 random characters followed by suffixes like -a, -b, -c, -d, -f, or -z
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-shapesecurity.json
  const headerNames = getHeaderNames(headers)
  for (const name of headerNames) {
    if (/^x-[a-z0-9]{8}-[abcdfz]$/i.test(name)) {
      return byHeaders('shapesecurity')
    }
  }

  // Shape Security: Check for 'shapesecurity' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-shapesecurity.json
  if (htmlHas('shapesecurity')) {
    return byHtml('shapesecurity')
  }

  // Kasada: Check for x-kasada or x-kasada-challenge headers
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-kasada.json
  if (hasAnyHeader(['x-kasada', 'x-kasada-challenge'])) {
    return byHeaders('kasada')
  }

  // Kasada: Check for __kasada global object or kasada.js script in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-kasada.json
  if (hasAnyHtml(['__kasada', 'kasada.js'])) {
    return byHtml('kasada')
  }

  // Imperva/Incapsula: Check for x-cdn header with 'Incapsula' value or x-iinfo header
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
  if (getHeader('x-cdn') === 'Incapsula' || hasAnyHeader(['x-iinfo'])) {
    return byHeaders('imperva')
  }

  // Imperva/Incapsula: Check for 'incapsula' or 'imperva' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
  if (hasAnyHtml(['incapsula', 'imperva'])) {
    return byHtml('imperva')
  }

  // Imperva/Incapsula: incap_ses_, visid_incap_, or reese84 cookies
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
  if (hasAnyCookie(['incap_ses_', 'visid_incap_', 'reese84='])) {
    return byCookies('imperva')
  }

  // Reblaze: rbzid or rbzsessionid cookies
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-reblaze.json
  if (hasAnyCookie(['rbzid=', 'rbzsessionid='])) {
    return byCookies('reblaze')
  }

  // Reblaze: Check for 'reblaze' text in response html
  if (htmlHas('reblaze')) {
    return byHtml('reblaze')
  }

  // Cheq: Check for CheqSdk or cheqzone.com in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-cheq.json
  if (hasAnyHtml(['CheqSdk', 'cheqzone.com'])) {
    return byHtml('cheq')
  }

  // Cheq: Check for cheqzone.com or cheq.ai in URL
  if (hasAnyUrlRegex('cheqzone\\.com', 'cheq\\.ai')) {
    return byUrl('cheq')
  }

  // Sucuri: Check for 'sucuri' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-sucuri.json
  if (htmlHas('sucuri')) {
    return byHtml('sucuri')
  }

  // ThreatMetrix: Check for 'ThreatMetrix' in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-threatmetrix.json
  if (htmlHas('ThreatMetrix')) {
    return byHtml('threatmetrix')
  }

  // ThreatMetrix: Check for fp/check.js fingerprint endpoint in URL
  if (hasAnyUrl('fp/check.js')) {
    return byUrl('threatmetrix')
  }

  // Meetrics: Check for 'meetrics' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-meetrics.json
  if (htmlHas('meetrics')) {
    return byHtml('meetrics')
  }

  // Meetrics: Check for meetrics.com in URL
  if (urlHas('meetrics\\.com', true)) {
    return byUrl('meetrics')
  }

  // Ocule: Check for ocule.co.uk in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-ocule.json
  if (htmlHas('ocule.co.uk')) {
    return byHtml('ocule')
  }

  // Ocule: Check for ocule.co.uk in URL
  if (urlHas('ocule\\.co\\.uk', true)) {
    return byUrl('ocule')
  }

  // reCAPTCHA: Check for recaptcha/api, google.com/recaptcha, gstatic.com/recaptcha, or recaptcha.net in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-recaptcha.json
  if (
    hasAnyUrl('recaptcha/api', 'gstatic.com/recaptcha', 'recaptcha.net') ||
    hasAnyUrlRegex('google\\.com/recaptcha')
  ) {
    return byUrl('recaptcha')
  }

  // reCAPTCHA: Check for grecaptcha API usage in html (JavaScript indicator)
  // Note: plain "grecaptcha" is too broad (e.g. ".grecaptcha-badge" CSS appears on normal YouTube pages)
  if (
    htmlHas(
      '\\b(?:window\\.)?grecaptcha\\s*\\.(?:execute|render|ready|getResponse|enterprise)\\b',
      true
    ) ||
    htmlHas('\\b(?:window\\.)?grecaptcha\\s*\\(', true) ||
    htmlHas('\\b__grecaptcha_cfg\\b', true)
  ) {
    return byHtml('recaptcha')
  }

  // reCAPTCHA: Check for g-recaptcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-recaptcha.json
  if (htmlHas('g-recaptcha')) {
    return byHtml('recaptcha')
  }

  // hCaptcha: Check for hcaptcha.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-hcaptcha.json
  if (urlHas('hcaptcha\\.com', true)) {
    return byUrl('hcaptcha')
  }

  // hCaptcha: Check for hcaptcha.com API domain or h-captcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-hcaptcha.json
  // Note: bare 'hcaptcha' matches too broadly (could appear in articles discussing hCaptcha)
  if (hasAnyHtml(['hcaptcha.com', 'h-captcha'])) {
    return byHtml('hcaptcha')
  }

  // FunCaptcha (Arkose Labs): Check for arkoselabs.com or funcaptcha in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-funcaptcha.json
  if (urlHas('arkoselabs\\.com', true) || urlHas('funcaptcha')) {
    return byUrl('funcaptcha')
  }

  // FunCaptcha (Arkose Labs): Check for arkoselabs.com API domain or funcaptcha in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-funcaptcha.json
  // Note: bare 'arkose' matches too broadly (e.g. Facebook bundles Arkose SDK for login without blocking content)
  if (hasAnyHtml(['arkoselabs.com', 'funcaptcha'])) {
    return byHtml('funcaptcha')
  }

  // GeeTest: Check for geetest.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-geetest.json
  if (urlHas('geetest\\.com', true)) {
    return byUrl('geetest')
  }

  // GeeTest: Check for geetest object or text in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-geetest.json
  // Note: bare 'gt.js' removed (too generic, any script named gt.js would match)
  if (htmlHas('geetest')) {
    return byHtml('geetest')
  }

  // Cloudflare Turnstile: Check for challenges.cloudflare.com/turnstile in URL
  if (urlHas('challenges\\.cloudflare\\.com/turnstile', true)) {
    return byUrl('cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for cf-turnstile class or turnstile API script in html
  // Note: bare 'turnstile' matches too broadly (common English word)
  if (hasAnyHtml(['cf-turnstile', 'challenges.cloudflare.com/turnstile'])) {
    return byHtml('cloudflare-turnstile')
  }

  // Friendly Captcha: Check for friendlycaptcha.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-friendlycaptcha.json
  if (urlHas('friendlycaptcha\\.com', true)) {
    return byUrl('friendly-captcha')
  }

  // Friendly Captcha: Check for frc-captcha container or friendlyChallenge object in html
  if (hasAnyHtml(['frc-captcha', 'friendlyChallenge'])) {
    return byHtml('friendly-captcha')
  }

  // Captcha.eu: Check for captcha.eu in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-captchaeu.json
  if (urlHas('captcha\\.eu', true)) {
    return byUrl('captcha-eu')
  }

  // Captcha.eu: Check for CaptchaEU or captchaeu in html
  if (hasAnyHtml(['CaptchaEU', 'captchaeu'])) {
    return byHtml('captcha-eu')
  }

  // QCloud Captcha (Tencent): Check for turing.captcha.qcloud.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-qcloud.json
  if (urlHas('turing\\.captcha\\.qcloud\\.com', true)) {
    return byUrl('qcloud-captcha')
  }

  // QCloud Captcha: Check for TencentCaptcha or turing.captcha in html
  if (hasAnyHtml(['TencentCaptcha', 'turing.captcha'])) {
    return byHtml('qcloud-captcha')
  }

  // AliExpress CAPTCHA: Check for punish?x5secdata in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-aliexpress.json
  if (urlHas('punish\\?x5secdata', true)) {
    return byUrl('aliexpress-captcha')
  }

  // AliExpress CAPTCHA: Check for x5secdata in html
  if (htmlHas('x5secdata')) {
    return byHtml('aliexpress-captcha')
  }

  // LinkedIn: trkCode=bf cookie ("bot filter") is set when LinkedIn blocks a request
  if (hasCookie('trkCode=bf')) {
    return byCookies('linkedin')
  }

  // YouTube: empty title pattern indicates a degraded response requiring BotGuard JS attestation
  // Normal pages have `<title>Video Title - YouTube</title>`, bots get `<title> - YouTube</title>`
  if (htmlHas('<title>\\s*-\\s*YouTube<\\/title>', true)) {
    return byHtml('youtube')
  }

  // AWS WAF: Check for x-amzn-waf-action or x-amzn-requestid headers
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-aws-waf.json
  if (hasAnyHeader(['x-amzn-waf-action', 'x-amzn-requestid'])) {
    return byHeaders('aws-waf')
  }

  // AWS WAF: Check for aws-waf or awswaf text in html
  if (hasAnyHtml(['aws-waf', 'awswaf'])) {
    return byHtml('aws-waf')
  }

  // AWS WAF: aws-waf-token cookie
  if (hasCookie('aws-waf-token=')) {
    return byCookies('aws-waf')
  }

  return createResult(false, null, null)
}

const isAntibot = (input = {}) => {
  const { headers, html, body, url } = input
  return detect({ headers, html: html || body, url })
}

module.exports = isAntibot
module.exports.debug = debug
module.exports.createTestPattern = createTestPattern
module.exports.createHasCookie = createHasCookie
