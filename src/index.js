'use strict'

const { splitSetCookieString } = require('cookie-es')
const { parseUrl } = require('@metascraper/helpers')
const debug = require('debug-logfmt')('is-antibot')

const providersData = require('./providers.json')

const DETECTION = {
  headers: 'headers',
  cookies: 'cookies',
  html: 'html',
  url: 'url',
  status_code: 'statusCode'
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
    if (pattern && pattern.type === 'contains') {
      return lowerValue.includes(pattern.value)
    }
    return lowerValue.includes(pattern.toLowerCase())
  }
}

const createResult = (detected, provider, detection = null) => {
  debug({ detected, provider, detection })
  return { detected, provider, detection }
}

const createHasCookie = (headers, getHeader = createGetHeader(headers)) => {
  let setCookieHeader
  let cookies

  const getSetCookieHeader = () => {
    if (setCookieHeader === undefined) {
      setCookieHeader = getHeader('set-cookie')
    }
    return setCookieHeader
  }

  const getCookies = () => {
    if (cookies === undefined) {
      cookies = splitSetCookieString(getSetCookieHeader())
    }
    return cookies
  }

  const hasAnyCookie = (cookieList, patterns) => {
    for (const cookie of cookieList) {
      for (const pattern of patterns) {
        if (cookie.startsWith(pattern)) return true
      }
    }
    return false
  }

  return patternList => {
    const patterns = Array.isArray(patternList) ? patternList : [patternList]
    const rawSetCookie = getSetCookieHeader()

    if (
      !rawSetCookie ||
      (Array.isArray(rawSetCookie) && rawSetCookie.length === 0)
    ) {
      return false
    }

    if (typeof rawSetCookie === 'string') {
      let hasCandidate = false
      for (const pattern of patterns) {
        if (rawSetCookie.includes(pattern)) {
          hasCandidate = true
          break
        }
      }
      if (!hasCandidate) return false
    }

    const parsedCookies = getCookies()
    return hasAnyCookie(parsedCookies, patterns)
  }
}

const getHeaderNames = headers => {
  let value
  return () => {
    if (value === undefined) {
      value =
        typeof headers.keys === 'function'
          ? Array.from(headers.keys())
          : Object.keys(headers)
    }
    return value
  }
}

const createRegExp = (pattern, flags = '') => new RegExp(pattern, flags)

const createCompiledDetection = (detection, matches) => ({
  type: detection.type,
  domain: detection.domain,
  matches
})

const compileHeaderRule = rule => {
  if (rule.equals !== undefined) {
    return ({ getHeader }) => getHeader(rule.header) === rule.equals
  }

  if (rule.startsWith !== undefined) {
    return ({ getHeader }) =>
      getHeader(rule.header)?.startsWith(rule.startsWith)
  }

  if (rule.exists && rule.except !== undefined) {
    const except = rule.except.toLowerCase()
    return ({ getHeader }) => {
      const value = getHeader(rule.header)
      return Boolean(value) && String(value).toLowerCase() !== except
    }
  }

  if (rule.exists) {
    return ({ getHeader }) => Boolean(getHeader(rule.header))
  }

  if (rule.oneOf !== undefined) {
    const oneOf = new Set(rule.oneOf)
    return ({ getHeader }) => oneOf.has(getHeader(rule.header))
  }

  if (typeof rule.headerNamePattern === 'string') {
    const regex = createRegExp(rule.headerNamePattern, rule.flags ?? '')
    return ({ headerNames }) => headerNames().some(name => regex.test(name))
  }

  throw new TypeError('Invalid header rule shape')
}

const compileTextPattern = rule => {
  if (rule.contains !== undefined) {
    return { type: 'contains', value: rule.contains.toLowerCase() }
  }
  return createRegExp(rule.regex, rule.flags ?? 'i')
}

const compileTextDetection = (detection, getPatternTester) => {
  const patterns = detection.rules.map(compileTextPattern)
  return createCompiledDetection(detection, context => {
    const testPattern = getPatternTester(context)
    for (const pattern of patterns) {
      if (testPattern(pattern)) return true
    }
    return false
  })
}

const DETECTION_COMPILERS = {
  cookies: detection => {
    const cookiePatterns = detection.rules.map(rule => rule.cookie)
    return createCompiledDetection(detection, ({ hasCookie }) =>
      hasCookie(cookiePatterns)
    )
  },
  html: detection => compileTextDetection(detection, ({ htmlHas }) => htmlHas),
  url: detection => compileTextDetection(detection, ({ urlHas }) => urlHas),
  headers: detection => {
    const headerRules = detection.rules.map(compileHeaderRule)
    return createCompiledDetection(detection, context => {
      for (const test of headerRules) {
        if (test(context)) return true
      }
      return false
    })
  },
  status_code: detection => {
    const statusCodes = detection.rules.map(rule => rule.status)
    return createCompiledDetection(detection, ({ statusCode }) =>
      statusCodes.includes(statusCode)
    )
  }
}

const compileDetection = detection =>
  DETECTION_COMPILERS[detection.type](detection)

const compileProviders = ({ providers = [] } = {}) =>
  providers.map(provider => ({
    name: provider.name,
    detections: provider.detections.map(compileDetection)
  }))

const detectWithProviders = (
  compiledProviders,
  { headers = {}, html = '', url = '', statusCode } = {}
) => {
  const getHeader = createGetHeader(headers)
  const hasCookie = createHasCookie(headers, getHeader)
  const htmlHas = createTestPattern(html)
  const urlHas = createTestPattern(url)
  const headerNames = getHeaderNames(headers)

  let domain
  const context = {
    getHeader,
    headerNames,
    hasCookie,
    htmlHas,
    urlHas,
    statusCode
  }

  for (const provider of compiledProviders) {
    for (const detection of provider.detections) {
      if (detection.domain) {
        if (domain === undefined) domain = parseUrl(url).domain
        if (detection.domain !== domain) continue
      }
      if (!detection.matches(context)) continue
      return createResult(
        true,
        provider.name,
        DETECTION[detection.type] || detection.type
      )
    }
  }

  return createResult(false, null, null)
}

const COMPILED_PROVIDERS = compileProviders(providersData)

const normalizeInput = input => {
  const { headers, html, body, url, statusCode, status } = input || {}
  return {
    headers,
    html: html || body,
    url,
    statusCode: statusCode ?? status
  }
}

const createDetector = providers => {
  const compiledProviders = compileProviders(providers)
  return input => detectWithProviders(compiledProviders, normalizeInput(input))
}

const isAntibot = (input = {}) =>
  detectWithProviders(COMPILED_PROVIDERS, normalizeInput(input))

module.exports = isAntibot
module.exports.debug = debug
module.exports.createTestPattern = createTestPattern
module.exports.createHasCookie = createHasCookie
module.exports.createDetector = createDetector
