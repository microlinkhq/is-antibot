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

const createResult = (detected, provider) => {
  debug({ detected, provider })
  return { detected, provider }
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

  // CloudFlare: Check for cf-mitigated header with 'challenge' value
  // Official docs: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader('cf-mitigated') === 'challenge') {
    return createResult(true, 'cloudflare')
  }

  // Cloudflare: cf_clearance cookie indicates Cloudflare challenge flow
  if (hasCookie('cf_clearance=')) {
    return createResult(true, 'cloudflare')
  }

  // Vercel: Check for x-vercel-mitigated header with 'challenge' value
  // Solver reference: https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (getHeader('x-vercel-mitigated') === 'challenge') {
    return createResult(true, 'vercel')
  }

  // Akamai: Check for akamai-cache-status header starting with 'Error'
  // Official docs: https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (getHeader('akamai-cache-status')?.startsWith('Error')) {
    return createResult(true, 'akamai')
  }

  // Akamai: Check for additional identifying headers (akamai-grn, x-akamai-session-info)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/akamai.json
  if (getHeader('akamai-grn') || getHeader('x-akamai-session-info')) {
    return createResult(true, 'akamai')
  }

  // Akamai: _abck bot manager tracking cookie
  if (hasCookie('_abck=')) {
    return createResult(true, 'akamai')
  }

  // Akamai: Bot Manager API namespace (bmak) in html
  if (htmlHas('bmak.')) {
    return createResult(true, 'akamai')
  }

  // DataDome: Check for x-dd-b header with values '1' (soft challenge) or '2' (hard challenge/CAPTCHA)
  // Official docs: https://docs.datadome.co/reference/validate-request
  if (['1', '2'].includes(getHeader('x-dd-b'))) {
    return createResult(true, 'datadome')
  }

  // DataDome: Check for x-datadome or x-datadome-cid header presence
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/datadome.json
  if (getHeader('x-datadome') || getHeader('x-datadome-cid')) {
    return createResult(true, 'datadome')
  }

  // DataDome: datadome tracking cookie
  if (hasCookie('datadome=')) {
    return createResult(true, 'datadome')
  }

  // PerimeterX: Check for X-PX-Authorization header (primary indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/perimeterx.json#L71-L84
  if (getHeader('x-px-authorization')) {
    return createResult(true, 'perimeterx')
  }

  // PerimeterX: Check for window._pxAppId, pxInit, or _pxAction in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/perimeterx.json#L130-L137
  if (htmlHas('window._pxAppId') || htmlHas('pxInit') || htmlHas('_pxAction')) {
    return createResult(true, 'perimeterx')
  }

  // PerimeterX: _px3 or _pxhd cookies
  if (hasCookie('_px3=') || hasCookie('_pxhd=')) {
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
  if (htmlHas('shapesecurity')) {
    return createResult(true, 'shapesecurity')
  }

  // Kasada: Check for x-kasada or x-kasada-challenge headers
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/kasada.json#L57-L85
  if (getHeader('x-kasada') || getHeader('x-kasada-challenge')) {
    return createResult(true, 'kasada')
  }

  // Kasada: Check for __kasada global object or kasada.js script in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/kasada.json#L117-L144
  if (htmlHas('__kasada') || htmlHas('kasada.js')) {
    return createResult(true, 'kasada')
  }

  // Imperva/Incapsula: Check for x-cdn header with 'Incapsula' value or x-iinfo header
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/incapsula.json#L86-L109
  if (getHeader('x-cdn') === 'Incapsula' || getHeader('x-iinfo')) {
    return createResult(true, 'imperva')
  }

  // Imperva/Incapsula: Check for 'incapsula' or 'imperva' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/incapsula.json#L111-L124
  if (htmlHas('incapsula') || htmlHas('imperva')) {
    return createResult(true, 'imperva')
  }

  // Imperva/Incapsula: incap_ses_, visid_incap_, or reese84 cookies
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/incapsula.json
  if (
    hasCookie('incap_ses_') ||
    hasCookie('visid_incap_') ||
    hasCookie('reese84=')
  ) {
    return createResult(true, 'imperva')
  }

  // Reblaze: rbzid or rbzsessionid cookies
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/reblaze.json
  if (hasCookie('rbzid=') || hasCookie('rbzsessionid=')) {
    return createResult(true, 'reblaze')
  }

  // Reblaze: Check for 'reblaze' text in response html
  if (htmlHas('reblaze')) {
    return createResult(true, 'reblaze')
  }

  // Cheq: Check for CheqSdk or cheqzone.com in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/cheq.json
  if (htmlHas('CheqSdk') || htmlHas('cheqzone.com')) {
    return createResult(true, 'cheq')
  }

  // Cheq: Check for cheqzone.com or cheq.ai in URL
  if (urlHas('cheqzone\\.com', true) || urlHas('cheq\\.ai', true)) {
    return createResult(true, 'cheq')
  }

  // Sucuri: Check for 'sucuri' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/sucuri.json
  if (htmlHas('sucuri')) {
    return createResult(true, 'sucuri')
  }

  // ThreatMetrix: Check for 'ThreatMetrix' in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/threatmetrix.json
  if (htmlHas('ThreatMetrix')) {
    return createResult(true, 'threatmetrix')
  }

  // ThreatMetrix: Check for fp/check.js fingerprint endpoint in URL
  if (urlHas('fp/check.js')) {
    return createResult(true, 'threatmetrix')
  }

  // Meetrics: Check for 'meetrics' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/meetrics.json
  if (htmlHas('meetrics')) {
    return createResult(true, 'meetrics')
  }

  // Meetrics: Check for meetrics.com in URL
  if (urlHas('meetrics\\.com', true)) {
    return createResult(true, 'meetrics')
  }

  // Ocule: Check for ocule.co.uk in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/ocule.json
  if (htmlHas('ocule.co.uk')) {
    return createResult(true, 'ocule')
  }

  // Ocule: Check for ocule.co.uk in URL
  if (urlHas('ocule\\.co\\.uk', true)) {
    return createResult(true, 'ocule')
  }

  // reCAPTCHA: Check for recaptcha/api, google.com/recaptcha, gstatic.com/recaptcha, or recaptcha.net in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L13-L48
  if (
    urlHas('recaptcha/api') ||
    urlHas('google\\.com/recaptcha', true) ||
    urlHas('gstatic.com/recaptcha') ||
    urlHas('recaptcha.net')
  ) {
    return createResult(true, 'recaptcha')
  }

  // reCAPTCHA: Check for grecaptcha global object in html (primary JavaScript indicator)
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L51-L58
  if (htmlHas('grecaptcha')) {
    return createResult(true, 'recaptcha')
  }

  // reCAPTCHA: Check for g-recaptcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/recaptcha.json#L66-L73
  if (htmlHas('g-recaptcha')) {
    return createResult(true, 'recaptcha')
  }

  // hCaptcha: Check for hcaptcha.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L13-L22
  if (urlHas('hcaptcha\\.com', true)) {
    return createResult(true, 'hcaptcha')
  }

  // hCaptcha: Check for hcaptcha object in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L42-L50
  if (htmlHas('hcaptcha')) {
    return createResult(true, 'hcaptcha')
  }

  // hCaptcha: Check for h-captcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/hcaptcha.json#L51-L58
  if (htmlHas('h-captcha')) {
    return createResult(true, 'hcaptcha')
  }

  // FunCaptcha (Arkose Labs): Check for arkoselabs.com or funcaptcha in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/funcaptcha.json#L13-L40
  if (urlHas('arkoselabs\\.com', true) || urlHas('funcaptcha')) {
    return createResult(true, 'funcaptcha')
  }

  // FunCaptcha (Arkose Labs): Check for funcaptcha or arkose text in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/funcaptcha.json#L42-L55
  if (htmlHas('funcaptcha') || htmlHas('arkose')) {
    return createResult(true, 'funcaptcha')
  }

  // GeeTest: Check for geetest.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L13-L43
  if (urlHas('geetest\\.com', true)) {
    return createResult(true, 'geetest')
  }

  // GeeTest: Check for geetest object or text in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L45-L52
  if (htmlHas('geetest')) {
    return createResult(true, 'geetest')
  }

  // GeeTest: Check for gt.js script in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/geetest.json#L53-L60
  if (htmlHas('gt.js')) {
    return createResult(true, 'geetest')
  }

  // Cloudflare Turnstile: Check for challenges.cloudflare.com/turnstile in URL
  if (urlHas('challenges\\.cloudflare\\.com/turnstile', true)) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for cf-turnstile class in html
  if (htmlHas('cf-turnstile')) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for turnstile text in html
  if (htmlHas('turnstile')) {
    return createResult(true, 'cloudflare-turnstile')
  }

  // Friendly Captcha: Check for friendlycaptcha.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/friendlycaptcha.json
  if (urlHas('friendlycaptcha\\.com', true)) {
    return createResult(true, 'friendly-captcha')
  }

  // Friendly Captcha: Check for frc-captcha container or friendlyChallenge object in html
  if (htmlHas('frc-captcha') || htmlHas('friendlyChallenge')) {
    return createResult(true, 'friendly-captcha')
  }

  // Captcha.eu: Check for captcha.eu in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/captchaeu.json
  if (urlHas('captcha\\.eu', true)) {
    return createResult(true, 'captcha-eu')
  }

  // Captcha.eu: Check for CaptchaEU or captchaeu in html
  if (htmlHas('CaptchaEU') || htmlHas('captchaeu')) {
    return createResult(true, 'captcha-eu')
  }

  // QCloud Captcha (Tencent): Check for turing.captcha.qcloud.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/qcloud.json
  if (urlHas('turing\\.captcha\\.qcloud\\.com', true)) {
    return createResult(true, 'qcloud-captcha')
  }

  // QCloud Captcha: Check for TencentCaptcha or turing.captcha in html
  if (htmlHas('TencentCaptcha') || htmlHas('turing.captcha')) {
    return createResult(true, 'qcloud-captcha')
  }

  // AliExpress CAPTCHA: Check for punish?x5secdata in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/aliexpress.json
  if (urlHas('punish\\?x5secdata', true)) {
    return createResult(true, 'aliexpress-captcha')
  }

  // AliExpress CAPTCHA: Check for x5secdata in html
  if (htmlHas('x5secdata')) {
    return createResult(true, 'aliexpress-captcha')
  }

  // LinkedIn: trkCode=bf cookie ("bot filter") is set when LinkedIn blocks a request
  if (hasCookie('trkCode=bf')) {
    return createResult(true, 'linkedin')
  }

  // YouTube: empty title pattern indicates a degraded response requiring BotGuard JS attestation
  // Normal pages have `<title>Video Title - YouTube</title>`, bots get `<title> - YouTube</title>`
  if (htmlHas('<title>\\s*-\\s*YouTube<\\/title>', true)) {
    return createResult(true, 'youtube')
  }

  // AWS WAF: Check for x-amzn-waf-action or x-amzn-requestid headers
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/aws-waf.json
  if (getHeader('x-amzn-waf-action') || getHeader('x-amzn-requestid')) {
    return createResult(true, 'aws-waf')
  }

  // AWS WAF: Check for aws-waf or awswaf text in html
  if (htmlHas('aws-waf') || htmlHas('awswaf')) {
    return createResult(true, 'aws-waf')
  }

  // AWS WAF: aws-waf-token cookie
  if (hasCookie('aws-waf-token=')) {
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
module.exports.createTestPattern = createTestPattern
module.exports.createHasCookie = createHasCookie
