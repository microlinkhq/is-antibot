'use strict'

const debug = require('debug-logfmt')('is-antibot')

const getHeader = (headers, name) =>
  typeof headers.get === 'function' ? headers.get(name) : headers[name]

const getCookie = (headers, name, useStartsWith = false) => {
  const cookieHeader =
    getHeader(headers, 'cookie') || getHeader(headers, 'set-cookie')
  if (!cookieHeader) return null
  const cookies =
    typeof cookieHeader === 'string' ? [cookieHeader] : cookieHeader
  for (const cookie of cookies) {
    if (useStartsWith) {
      // For patterns, check if any cookie name starts with the pattern
      const cookiePairs = cookie.split(';')
      for (const pair of cookiePairs) {
        const cookieName = pair.trim().split('=')[0]
        if (
          cookieName &&
          cookieName.toLowerCase().startsWith(name.toLowerCase())
        ) {
          return pair.trim().split('=')[1] || ''
        }
      }
    } else {
      const match = cookie.match(
        new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*([^;]*)`)
      )
      if (match) return match[1]
    }
  }
  return null
}

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

// Detection rules with confidence scoring
const detectors = [
  // CloudFlare
  {
    name: 'cloudflare',
    detect: ({ headers }) => {
      // https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
      if (getHeader(headers, 'cf-mitigated') === 'challenge') return 100
      if (
        getHeader(headers, 'cf-ray') &&
        getHeader(headers, 'server') === 'cloudflare'
      ) {
        return 85
      }
      return 0
    }
  },
  // Vercel
  {
    name: 'vercel',
    detect: ({ headers }) => {
      // https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
      if (getHeader(headers, 'x-vercel-mitigated') === 'challenge') return 100
      return 0
    }
  },
  // Akamai
  {
    name: 'akamai',
    detect: ({ headers }) => {
      // https://techdocs.akamai.com/property-mgr/docs/return-cache-status
      const cacheStatus = getHeader(headers, 'akamai-cache-status')
      if (cacheStatus?.startsWith('Error')) return 100
      if (getCookie(headers, '_abck')) return 90
      if (getCookie(headers, 'ak_bmsc')) return 85
      if (
        getHeader(headers, 'akamai-grn') ||
        getHeader(headers, 'x-akamai-session-info')
      ) {
        return 80
      }
      return 0
    }
  },
  // DataDome
  {
    name: 'datadome',
    detect: ({ headers }) => {
      // https://docs.datadome.co/reference/validate-request
      const xDdB = getHeader(headers, 'x-dd-b')
      if (['1', '2'].includes(xDdB)) return 100
      if (getCookie(headers, 'datadome')) return 95
      if (getHeader(headers, 'x-datadome')) return 90
      return 0
    }
  },
  // PerimeterX
  {
    name: 'perimeterx',
    detect: ({ headers, body }) => {
      if (getHeader(headers, 'x-px-authorization')) return 100
      if (getCookie(headers, '_px3')) return 100
      if (getCookie(headers, '_px2')) return 95
      if (getCookie(headers, '_pxhd') || getCookie(headers, '_pxvid')) return 85
      if (body && testPattern(body, 'window._pxAppId')) return 90
      return 0
    }
  },
  // Shape Security
  {
    name: 'shapesecurity',
    detect: ({ headers, body }) => {
      // Dynamic header patterns: x-[8chars]-[abcdfz]
      const headerNames = Object.keys(headers)
      for (const name of headerNames) {
        if (/^x-[a-z0-9]{8}-[abcdfz]$/i.test(name)) return 100
      }
      // Cookie pattern: 8-character name with |1|0| or |1|1| pattern
      const cookieHeader =
        getHeader(headers, 'cookie') || getHeader(headers, 'set-cookie')
      if (
        cookieHeader &&
        /[A-Za-z0-9]{8}=[^;]*\|1\|[01]\|/.test(cookieHeader)
      ) {
        return 95
      }
      if (body && testPattern(body, 'shapesecurity')) return 85
      return 0
    }
  },
  // Kasada
  {
    name: 'kasada',
    detect: ({ headers, body }) => {
      if (
        getHeader(headers, 'x-kasada') ||
        getHeader(headers, 'x-kasada-challenge')
      ) {
        return 90
      }
      if (getCookie(headers, 'kas.js')) return 95
      if (getCookie(headers, 'kas_challenge')) return 90
      if (
        body &&
        (testPattern(body, '__kasada') || testPattern(body, 'kasada.js'))
      ) {
        return 85
      }
      return 0
    }
  },
  // Imperva/Incapsula
  {
    name: 'imperva',
    detect: ({ headers, body }) => {
      if (
        getCookie(headers, 'visid_incap', true) ||
        getCookie(headers, 'incap_ses', true)
      ) {
        return 100
      }
      if (
        getHeader(headers, 'x-cdn') === 'Incapsula' ||
        getHeader(headers, 'x-iinfo')
      ) {
        return 95
      }
      if (
        body &&
        (testPattern(body, 'incapsula') || testPattern(body, 'imperva'))
      ) {
        return 85
      }
      return 0
    }
  },
  // reCAPTCHA
  {
    name: 'recaptcha',
    detect: ({ body, url }) => {
      if (
        url &&
        (testPattern(url, 'recaptcha/api') ||
          testPattern(url, 'google\\.com/recaptcha', true))
      ) {
        return 100
      }
      if (body && testPattern(body, 'grecaptcha')) return 100
      if (body && testPattern(body, 'g-recaptcha')) return 95
      if (body && testPattern(body, 'recaptcha')) return 85
      return 0
    }
  },
  // hCaptcha
  {
    name: 'hcaptcha',
    detect: ({ body, url }) => {
      if (url && testPattern(url, 'hcaptcha\\.com', true)) return 100
      if (body && testPattern(body, 'hcaptcha')) return 100
      if (body && testPattern(body, 'h-captcha')) return 95
      return 0
    }
  },
  // FunCaptcha (Arkose Labs)
  {
    name: 'funcaptcha',
    detect: ({ body, url }) => {
      if (
        url &&
        (testPattern(url, 'arkoselabs\\.com', true) ||
          testPattern(url, 'funcaptcha'))
      ) {
        return 100
      }
      if (
        body &&
        (testPattern(body, 'funcaptcha') || testPattern(body, 'arkose'))
      ) {
        return 95
      }
      return 0
    }
  },
  // GeeTest
  {
    name: 'geetest',
    detect: ({ body, url }) => {
      if (url && testPattern(url, 'geetest\\.com', true)) return 100
      if (body && testPattern(body, 'geetest')) return 95
      if (body && testPattern(body, 'gt.js')) return 90
      return 0
    }
  },
  // Cloudflare Turnstile
  {
    name: 'cloudflare-turnstile',
    detect: ({ body, url }) => {
      if (
        url &&
        testPattern(url, 'challenges\\.cloudflare\\.com/turnstile', true)
      ) {
        return 100
      }
      if (body && testPattern(body, 'cf-turnstile')) return 100
      if (body && testPattern(body, 'turnstile')) return 95
      return 0
    }
  },
  // AWS WAF
  {
    name: 'aws-waf',
    detect: ({ headers, body }) => {
      if (getCookie(headers, 'aws-waf-token')) return 100
      if (
        getHeader(headers, 'x-amzn-waf-action') ||
        getHeader(headers, 'x-amzn-requestid')
      ) {
        return 90
      }
      if (body && testPattern(body, 'aws-waf')) return 85
      return 0
    }
  }
]

module.exports = ({ headers = {}, body = '', url = '' } = {}) => {
  let detected = false
  let provider = null
  let confidence = 0
  const detections = []

  for (const detector of detectors) {
    const score = detector.detect({ headers, body, url })
    if (score > 0) {
      detections.push({ name: detector.name, confidence: score })
      if (score > confidence) {
        detected = true
        provider = detector.name
        confidence = score
      }
    }
  }

  // Sort detections by confidence
  detections.sort((a, b) => b.confidence - a.confidence)

  const result = { detected, provider, confidence }
  if (detections.length > 1) {
    result.detections = detections
  }

  debug({ detected, provider, confidence, detections: detections.length })
  return result
}

module.exports.debug = debug
