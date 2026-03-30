'use strict'

const { splitSetCookieString } = require('cookie-es')
const debug = require('debug-logfmt')('is-antibot')

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

const TECHNIQUE = {
  HEADERS: 'headers',
  COOKIES: 'cookies',
  HTML: 'html',
  URL: 'url'
}

const createResult = (detected, provider, technique = null) => {
  debug({ detected, provider, technique })
  return { detected, provider, technique }
}

const createHasCookie = headers => {
  const getHeader = createGetHeader(headers)
  return pattern =>
    splitSetCookieString(getHeader('set-cookie')).some(c =>
      c.startsWith(pattern)
    )
}

const detect = ({ headers = {}, html = '', url = '' } = {}) => {
  const getHeader = createGetHeader(headers)

  const hasCookie = createHasCookie(headers)

  const htmlHas = createTestPattern(html)

  const urlHas = createTestPattern(url)

  const detectByHeaders = provider =>
    createResult(true, provider, TECHNIQUE.HEADERS)

  const detectByCookies = provider =>
    createResult(true, provider, TECHNIQUE.COOKIES)

  const detectByHtml = provider => createResult(true, provider, TECHNIQUE.HTML)

  const detectByUrl = provider => createResult(true, provider, TECHNIQUE.URL)

  // CloudFlare: Check for cf-mitigated header with 'challenge' value
  // Official docs: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader('cf-mitigated') === 'challenge') {
    return detectByHeaders('cloudflare')
  }

  // Cloudflare: cf_clearance cookie indicates Cloudflare challenge flow
  if (hasCookie('cf_clearance=')) {
    return detectByCookies('cloudflare')
  }

  // Vercel: Check for x-vercel-mitigated header with 'challenge' value
  // Solver reference: https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (getHeader('x-vercel-mitigated') === 'challenge') {
    return detectByHeaders('vercel')
  }

  // Akamai: Check for akamai-cache-status header starting with 'Error'
  // Official docs: https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (getHeader('akamai-cache-status')?.startsWith('Error')) {
    return detectByHeaders('akamai')
  }

  // Akamai: Check for additional identifying headers (akamai-grn, x-akamai-session-info)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-akamai.json
  if (getHeader('akamai-grn') || getHeader('x-akamai-session-info')) {
    return detectByHeaders('akamai')
  }

  // Akamai: _abck bot manager tracking cookie
  if (hasCookie('_abck=')) {
    return detectByCookies('akamai')
  }

  // Akamai: Bot Manager API namespace (bmak) in html
  if (htmlHas('bmak.')) {
    return detectByHtml('akamai')
  }

  // DataDome: Check for x-dd-b header with values '1' (soft challenge) or '2' (hard challenge/CAPTCHA)
  // Official docs: https://docs.datadome.co/reference/validate-request
  if (['1', '2'].includes(getHeader('x-dd-b'))) {
    return detectByHeaders('datadome')
  }

  // DataDome: Check for x-datadome or x-datadome-cid header presence
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-datadome.json
  if (getHeader('x-datadome') || getHeader('x-datadome-cid')) {
    return detectByHeaders('datadome')
  }

  // DataDome: datadome tracking cookie
  if (hasCookie('datadome=')) {
    return detectByCookies('datadome')
  }

  // PerimeterX: Check for X-PX-Authorization header (primary indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-perimeterx.json
  if (getHeader('x-px-authorization')) {
    return detectByHeaders('perimeterx')
  }

  // PerimeterX: Check for window._pxAppId, pxInit, or _pxAction in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-perimeterx.json
  if (htmlHas('window._pxAppId') || htmlHas('pxInit') || htmlHas('_pxAction')) {
    return detectByHtml('perimeterx')
  }

  // PerimeterX: _px3 or _pxhd cookies
  if (hasCookie('_px3=') || hasCookie('_pxhd=')) {
    return detectByCookies('perimeterx')
  }

  // Shape Security: Check for dynamic header patterns x-[8chars]-[abcdfz]
  // These headers use 8 random characters followed by suffixes like -a, -b, -c, -d, -f, or -z
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-shapesecurity.json
  const headerNames = Object.keys(headers)
  for (const name of headerNames) {
    if (/^x-[a-z0-9]{8}-[abcdfz]$/i.test(name)) {
      return detectByHeaders('shapesecurity')
    }
  }

  // Shape Security: Check for 'shapesecurity' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-shapesecurity.json
  if (htmlHas('shapesecurity')) {
    return detectByHtml('shapesecurity')
  }

  // Kasada: Check for x-kasada or x-kasada-challenge headers
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-kasada.json
  if (getHeader('x-kasada') || getHeader('x-kasada-challenge')) {
    return detectByHeaders('kasada')
  }

  // Kasada: Check for __kasada global object or kasada.js script in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-kasada.json
  if (htmlHas('__kasada') || htmlHas('kasada.js')) {
    return detectByHtml('kasada')
  }

  // Imperva/Incapsula: Check for x-cdn header with 'Incapsula' value or x-iinfo header
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
  if (getHeader('x-cdn') === 'Incapsula' || getHeader('x-iinfo')) {
    return detectByHeaders('imperva')
  }

  // Imperva/Incapsula: Check for 'incapsula' or 'imperva' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
  if (htmlHas('incapsula') || htmlHas('imperva')) {
    return detectByHtml('imperva')
  }

  // Imperva/Incapsula: incap_ses_, visid_incap_, or reese84 cookies
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-incapsula.json
  if (
    hasCookie('incap_ses_') ||
    hasCookie('visid_incap_') ||
    hasCookie('reese84=')
  ) {
    return detectByCookies('imperva')
  }

  // Reblaze: rbzid or rbzsessionid cookies
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-reblaze.json
  if (hasCookie('rbzid=') || hasCookie('rbzsessionid=')) {
    return detectByCookies('reblaze')
  }

  // Reblaze: Check for 'reblaze' text in response html
  if (htmlHas('reblaze')) {
    return detectByHtml('reblaze')
  }

  // Cheq: Check for CheqSdk or cheqzone.com in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-cheq.json
  if (htmlHas('CheqSdk') || htmlHas('cheqzone.com')) {
    return detectByHtml('cheq')
  }

  // Cheq: Check for cheqzone.com or cheq.ai in URL
  if (urlHas('cheqzone\\.com', true) || urlHas('cheq\\.ai', true)) {
    return detectByUrl('cheq')
  }

  // Sucuri: Check for 'sucuri' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-sucuri.json
  if (htmlHas('sucuri')) {
    return detectByHtml('sucuri')
  }

  // ThreatMetrix: Check for 'ThreatMetrix' in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-threatmetrix.json
  if (htmlHas('ThreatMetrix')) {
    return detectByHtml('threatmetrix')
  }

  // ThreatMetrix: Check for fp/check.js fingerprint endpoint in URL
  if (urlHas('fp/check.js')) {
    return detectByUrl('threatmetrix')
  }

  // Meetrics: Check for 'meetrics' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-meetrics.json
  if (htmlHas('meetrics')) {
    return detectByHtml('meetrics')
  }

  // Meetrics: Check for meetrics.com in URL
  if (urlHas('meetrics\\.com', true)) {
    return detectByUrl('meetrics')
  }

  // Ocule: Check for ocule.co.uk in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-ocule.json
  if (htmlHas('ocule.co.uk')) {
    return detectByHtml('ocule')
  }

  // Ocule: Check for ocule.co.uk in URL
  if (urlHas('ocule\\.co\\.uk', true)) {
    return detectByUrl('ocule')
  }

  // reCAPTCHA: Check for recaptcha/api, google.com/recaptcha, gstatic.com/recaptcha, or recaptcha.net in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-recaptcha.json
  if (
    urlHas('recaptcha/api') ||
    urlHas('google\\.com/recaptcha', true) ||
    urlHas('gstatic.com/recaptcha') ||
    urlHas('recaptcha.net')
  ) {
    return detectByUrl('recaptcha')
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
    return detectByHtml('recaptcha')
  }

  // reCAPTCHA: Check for g-recaptcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-recaptcha.json
  if (htmlHas('g-recaptcha')) {
    return detectByHtml('recaptcha')
  }

  // hCaptcha: Check for hcaptcha.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-hcaptcha.json
  if (urlHas('hcaptcha\\.com', true)) {
    return detectByUrl('hcaptcha')
  }

  // hCaptcha: Check for hcaptcha.com API domain or h-captcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-hcaptcha.json
  // Note: bare 'hcaptcha' matches too broadly (could appear in articles discussing hCaptcha)
  if (htmlHas('hcaptcha.com') || htmlHas('h-captcha')) {
    return detectByHtml('hcaptcha')
  }

  // FunCaptcha (Arkose Labs): Check for arkoselabs.com or funcaptcha in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-funcaptcha.json
  if (urlHas('arkoselabs\\.com', true) || urlHas('funcaptcha')) {
    return detectByUrl('funcaptcha')
  }

  // FunCaptcha (Arkose Labs): Check for arkoselabs.com API domain or funcaptcha in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-funcaptcha.json
  // Note: bare 'arkose' matches too broadly (e.g. Facebook bundles Arkose SDK for login without blocking content)
  if (htmlHas('arkoselabs.com') || htmlHas('funcaptcha')) {
    return detectByHtml('funcaptcha')
  }

  // GeeTest: Check for geetest.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-geetest.json
  if (urlHas('geetest\\.com', true)) {
    return detectByUrl('geetest')
  }

  // GeeTest: Check for geetest object or text in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-geetest.json
  // Note: bare 'gt.js' removed (too generic, any script named gt.js would match)
  if (htmlHas('geetest')) {
    return detectByHtml('geetest')
  }

  // Cloudflare Turnstile: Check for challenges.cloudflare.com/turnstile in URL
  if (urlHas('challenges\\.cloudflare\\.com/turnstile', true)) {
    return detectByUrl('cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for cf-turnstile class or turnstile API script in html
  // Note: bare 'turnstile' matches too broadly (common English word)
  if (
    htmlHas('cf-turnstile') ||
    htmlHas('challenges.cloudflare.com/turnstile')
  ) {
    return detectByHtml('cloudflare-turnstile')
  }

  // Friendly Captcha: Check for friendlycaptcha.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-friendlycaptcha.json
  if (urlHas('friendlycaptcha\\.com', true)) {
    return detectByUrl('friendly-captcha')
  }

  // Friendly Captcha: Check for frc-captcha container or friendlyChallenge object in html
  if (htmlHas('frc-captcha') || htmlHas('friendlyChallenge')) {
    return detectByHtml('friendly-captcha')
  }

  // Captcha.eu: Check for captcha.eu in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-captchaeu.json
  if (urlHas('captcha\\.eu', true)) {
    return detectByUrl('captcha-eu')
  }

  // Captcha.eu: Check for CaptchaEU or captchaeu in html
  if (htmlHas('CaptchaEU') || htmlHas('captchaeu')) {
    return detectByHtml('captcha-eu')
  }

  // QCloud Captcha (Tencent): Check for turing.captcha.qcloud.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-qcloud.json
  if (urlHas('turing\\.captcha\\.qcloud\\.com', true)) {
    return detectByUrl('qcloud-captcha')
  }

  // QCloud Captcha: Check for TencentCaptcha or turing.captcha in html
  if (htmlHas('TencentCaptcha') || htmlHas('turing.captcha')) {
    return detectByHtml('qcloud-captcha')
  }

  // AliExpress CAPTCHA: Check for punish?x5secdata in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-aliexpress.json
  if (urlHas('punish\\?x5secdata', true)) {
    return detectByUrl('aliexpress-captcha')
  }

  // AliExpress CAPTCHA: Check for x5secdata in html
  if (htmlHas('x5secdata')) {
    return detectByHtml('aliexpress-captcha')
  }

  // LinkedIn: trkCode=bf cookie ("bot filter") is set when LinkedIn blocks a request
  if (hasCookie('trkCode=bf')) {
    return detectByCookies('linkedin')
  }

  // YouTube: empty title pattern indicates a degraded response requiring BotGuard JS attestation
  // Normal pages have `<title>Video Title - YouTube</title>`, bots get `<title> - YouTube</title>`
  if (htmlHas('<title>\\s*-\\s*YouTube<\\/title>', true)) {
    return detectByHtml('youtube')
  }

  // AWS WAF: Check for x-amzn-waf-action or x-amzn-requestid headers
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-aws-waf.json
  if (getHeader('x-amzn-waf-action') || getHeader('x-amzn-requestid')) {
    return detectByHeaders('aws-waf')
  }

  // AWS WAF: Check for aws-waf or awswaf text in html
  if (htmlHas('aws-waf') || htmlHas('awswaf')) {
    return detectByHtml('aws-waf')
  }

  // AWS WAF: aws-waf-token cookie
  if (hasCookie('aws-waf-token=')) {
    return detectByCookies('aws-waf')
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
