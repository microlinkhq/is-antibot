'use strict'

const { splitSetCookieString } = require('cookie-es')
const { parseUrl } = require('@metascraper/helpers')
const debug = require('debug-logfmt')('is-antibot')

const DETECTION = {
  HEADERS: 'headers',
  COOKIES: 'cookies',
  HTML: 'html',
  URL: 'url',
  STATUS_CODE: 'statusCode'
}

const createGetHeader = headers =>
  typeof headers.get === 'function'
    ? name => headers.get(name)
    : name => headers[name]

const createTestPattern = value => {
  if (!value) return () => false
  const lowerValue = value.toLowerCase()
  return pattern => {
    if (pattern instanceof RegExp) {
      try {
        return pattern.test(value)
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

const detect = ({ headers = {}, html = '', url = '', statusCode } = {}) => {
  const getHeader = createGetHeader(headers)
  const hasCookie = createHasCookie(headers)
  const htmlHas = createTestPattern(html)
  const urlHas = createTestPattern(url)

  const hasAnyHeader = headerNames =>
    headerNames.some(headerName => getHeader(headerName))

  const hasAnyCookie = cookieNames =>
    cookieNames.some(cookieName => hasCookie(cookieName))

  const hasAnyHtml = patterns => patterns.some(pattern => htmlHas(pattern))

  const hasAnyUrl = patterns => patterns.some(pattern => urlHas(pattern))

  const byHeaders = provider => createResult(true, provider, DETECTION.HEADERS)

  const byCookies = provider => createResult(true, provider, DETECTION.COOKIES)

  const byHtml = provider => createResult(true, provider, DETECTION.HTML)

  const byUrl = provider => createResult(true, provider, DETECTION.URL)

  const byStatusCode = provider =>
    createResult(true, provider, DETECTION.STATUS_CODE)

  // CloudFlare: Check for cf-mitigated header with 'challenge' value
  // Official docs: https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader('cf-mitigated') === 'challenge') {
    return byHeaders('cloudflare')
  }

  // Cloudflare: cf_clearance cookie indicates Cloudflare challenge flow
  if (hasAnyCookie(['cf_clearance='])) {
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
  if (hasAnyCookie(['_abck='])) {
    return byCookies('akamai')
  }

  // Akamai: Bot Manager API namespace (bmak) in html
  if (hasAnyHtml(['bmak.'])) {
    return byHtml('akamai')
  }

  // DataDome: Check for x-dd-b header with values '1' (soft challenge) or '2' (hard challenge/CAPTCHA)
  // Official docs: https://docs.datadome.co/reference/validate-request
  if (['1', '2'].includes(getHeader('x-dd-b'))) {
    return byHeaders('datadome')
  }

  // DataDome: x-datadome header presence.
  // Note: `x-datadome: protected` can appear on successful responses.
  const xDatadome = getHeader('x-datadome')
  if (xDatadome && String(xDatadome).toLowerCase() !== 'protected') {
    return byHeaders('datadome')
  }

  // DataDome: x-datadome-cid header presence
  if (hasAnyHeader(['x-datadome-cid'])) {
    return byHeaders('datadome')
  }

  // DataDome: datadome tracking cookie
  if (hasAnyCookie(['datadome='])) {
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
  if (hasAnyHtml(['shapesecurity'])) {
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
  if (hasAnyHtml(['reblaze'])) {
    return byHtml('reblaze')
  }

  // Cheq: Check for CheqSdk or cheqzone.com in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-cheq.json
  if (hasAnyHtml(['CheqSdk', 'cheqzone.com'])) {
    return byHtml('cheq')
  }

  // Cheq: Check for cheqzone.com or cheq.ai in URL
  if (hasAnyUrl([/cheqzone\.com/i, /cheq\.ai/i])) {
    return byUrl('cheq')
  }

  // Sucuri: Check for 'sucuri' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-sucuri.json
  if (hasAnyHtml(['sucuri'])) {
    return byHtml('sucuri')
  }

  // ThreatMetrix: Check for 'ThreatMetrix' in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-threatmetrix.json
  if (hasAnyHtml(['ThreatMetrix'])) {
    return byHtml('threatmetrix')
  }

  // ThreatMetrix: Check for fp/check.js fingerprint endpoint in URL
  if (hasAnyUrl(['fp/check.js'])) {
    return byUrl('threatmetrix')
  }

  // Meetrics: Check for 'meetrics' text in response html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-meetrics.json
  if (hasAnyHtml(['meetrics'])) {
    return byHtml('meetrics')
  }

  // Meetrics: Check for meetrics.com in URL
  if (hasAnyUrl([/meetrics\.com/i])) {
    return byUrl('meetrics')
  }

  // Ocule: Check for ocule.co.uk in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/antibot/detect-ocule.json
  if (hasAnyHtml(['ocule.co.uk'])) {
    return byHtml('ocule')
  }

  // Ocule: Check for ocule.co.uk in URL
  if (hasAnyUrl([/ocule\.co\.uk/i])) {
    return byUrl('ocule')
  }

  // reCAPTCHA: Check for recaptcha/api, google.com/recaptcha, gstatic.com/recaptcha, or recaptcha.net in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-recaptcha.json
  if (
    hasAnyUrl(['recaptcha/api', 'gstatic.com/recaptcha', 'recaptcha.net']) ||
    hasAnyUrl([/google\.com\/recaptcha/i])
  ) {
    return byUrl('recaptcha')
  }

  // reCAPTCHA: Check for grecaptcha API usage in html (JavaScript indicator)
  // Note: plain "grecaptcha" is too broad (e.g. ".grecaptcha-badge" CSS appears on normal YouTube pages)
  if (
    hasAnyHtml([
      /\b(?:window\.)?grecaptcha\s*\.(?:execute|render|ready|getResponse|enterprise)\b/i,
      /\b(?:window\.)?grecaptcha\s*\(/i,
      /\b__grecaptcha_cfg\b/i
    ])
  ) {
    return byHtml('recaptcha')
  }

  // reCAPTCHA: Check for g-recaptcha container class in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-recaptcha.json
  if (hasAnyHtml(['g-recaptcha'])) {
    return byHtml('recaptcha')
  }

  // hCaptcha: Check for hcaptcha.com domain in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-hcaptcha.json
  if (hasAnyUrl([/hcaptcha\.com/i])) {
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
  if (hasAnyUrl([/arkoselabs\.com/i]) || hasAnyUrl(['funcaptcha'])) {
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
  if (hasAnyUrl([/geetest\.com/i])) {
    return byUrl('geetest')
  }

  // GeeTest: Check for geetest object or text in html
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-geetest.json
  // Note: bare 'gt.js' removed (too generic, any script named gt.js would match)
  if (hasAnyHtml(['geetest'])) {
    return byHtml('geetest')
  }

  // Cloudflare Turnstile: Check for challenges.cloudflare.com/turnstile in URL
  if (hasAnyUrl([/challenges\.cloudflare\.com\/turnstile/i])) {
    return byUrl('cloudflare-turnstile')
  }

  // Cloudflare Turnstile: Check for cf-turnstile class or turnstile API script in html
  // Note: bare 'turnstile' matches too broadly (common English word)
  if (hasAnyHtml(['cf-turnstile', 'challenges.cloudflare.com/turnstile'])) {
    return byHtml('cloudflare-turnstile')
  }

  // Friendly Captcha: Check for friendlycaptcha.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-friendlycaptcha.json
  if (hasAnyUrl([/friendlycaptcha\.com/i])) {
    return byUrl('friendly-captcha')
  }

  // Friendly Captcha: Check for frc-captcha container or friendlyChallenge object in html
  if (hasAnyHtml(['frc-captcha', 'friendlyChallenge'])) {
    return byHtml('friendly-captcha')
  }

  // Captcha.eu: Check for captcha.eu in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-captchaeu.json
  if (hasAnyUrl([/captcha\.eu/i])) {
    return byUrl('captcha-eu')
  }

  // Captcha.eu: Check for CaptchaEU or captchaeu in html
  if (hasAnyHtml(['CaptchaEU', 'captchaeu'])) {
    return byHtml('captcha-eu')
  }

  // QCloud Captcha (Tencent): Check for turing.captcha.qcloud.com in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-qcloud.json
  if (hasAnyUrl([/turing\.captcha\.qcloud\.com/i])) {
    return byUrl('qcloud-captcha')
  }

  // QCloud Captcha: Check for TencentCaptcha or turing.captcha in html
  if (hasAnyHtml(['TencentCaptcha', 'turing.captcha'])) {
    return byHtml('qcloud-captcha')
  }

  // AliExpress CAPTCHA: Check for punish?x5secdata in URL
  // Reference: https://github.com/scrapfly/Antibot-Detector/blob/main/detectors/captcha/detect-aliexpress.json
  if (hasAnyUrl([/punish\?x5secdata/i])) {
    return byUrl('aliexpress-captcha')
  }

  // AliExpress CAPTCHA: Check for x5secdata in html
  if (hasAnyHtml(['x5secdata'])) {
    return byHtml('aliexpress-captcha')
  }

  // Reddit: blocked requests are served as HTML challenge pages.
  if (parseUrl(url).domain === 'reddit.com') {
    if (statusCode === 403) {
      return byStatusCode('reddit')
    }
    if (hasAnyHtml([/blocked by network security\./i])) {
      return byHtml('reddit')
    }
  }

  // LinkedIn: status 999 is LinkedIn's dedicated bot-detection response
  if (parseUrl(url).domain === 'linkedin.com' && statusCode === 999) {
    return byStatusCode('linkedin')
  }

  // Instagram: login page redirect indicates bot detection
  if (
    parseUrl(url).domain === 'instagram.com' &&
    hasAnyHtml([/<title>\s*Login\s*[•·]\s*Instagram\s*<\/title>/i])
  ) {
    return byHtml('instagram')
  }

  // YouTube: empty title pattern indicates a degraded response requiring BotGuard JS attestation
  // Normal pages have `<title>Video Title - YouTube</title>`, bots get `<title> - YouTube</title>`
  if (hasAnyHtml([/<title>\s*-\s*YouTube<\/title>/i])) {
    return byHtml('youtube')
  }

  // Anubis (Techaro BotStopper): challenge pages always contain the JSON script block
  // `<script id="anubis_challenge" type="application/json">` (hardcoded in web/index.templ)
  // and asset/API URLs under the Go constant `StaticPath = "/.within.website/x/cmd/anubis/"`.
  // Source: https://github.com/TecharoHQ/anubis
  if (
    hasAnyHtml([
      /<script id="anubis_challenge"/,
      '/.within.website/x/cmd/anubis/'
    ])
  ) {
    return byHtml('anubis')
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
  if (hasAnyCookie(['aws-waf-token='])) {
    return byCookies('aws-waf')
  }

  return createResult(false, null, null)
}

const isAntibot = (input = {}) => {
  const { headers, html, body, url, statusCode, status } = input
  return detect({
    headers,
    html: html || body,
    url,
    statusCode: statusCode ?? status
  })
}

module.exports = isAntibot
module.exports.debug = debug
module.exports.createTestPattern = createTestPattern
module.exports.createHasCookie = createHasCookie
