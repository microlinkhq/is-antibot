'use strict'

const { splitSetCookieString } = require('cookie-es')
const { parseUrl } = require('@metascraper/helpers')
const debug = require('debug-logfmt')('is-antibot')

const providersData = require('../providers/providers.json')

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
    return lowerValue.includes(pattern.toLowerCase())
  }
}

const createResult = (detected, provider, detection = null) => {
  debug({ detected, provider, detection })
  return { detected, provider, detection }
}

const createHasCookie = headers => {
  const getHeader = createGetHeader(headers)
  const cookies = splitSetCookieString(getHeader('set-cookie'))
  return patterns => {
    const cookiePatterns = Array.isArray(patterns) ? patterns : [patterns]
    return cookies.some(cookie =>
      cookiePatterns.some(pattern => cookie.startsWith(pattern))
    )
  }
}

const getHeaderNames = headers =>
  typeof headers.keys === 'function'
    ? Array.from(headers.keys())
    : Object.keys(headers)

const createSafeRegExp = (pattern, flags = '') => {
  try {
    return new RegExp(pattern, flags)
  } catch {
    return null
  }
}

const compileHeaderRule = rule => {
  if (typeof rule.header === 'string' && typeof rule.equals === 'string') {
    return { type: 'equals', header: rule.header, equals: rule.equals }
  }

  if (typeof rule.header === 'string' && typeof rule.startsWith === 'string') {
    return {
      type: 'startsWith',
      header: rule.header,
      startsWith: rule.startsWith
    }
  }

  if (
    typeof rule.header === 'string' &&
    rule.exists === true &&
    typeof rule.except === 'string'
  ) {
    return {
      type: 'existsExcept',
      header: rule.header,
      except: rule.except.toLowerCase()
    }
  }

  if (typeof rule.header === 'string' && rule.exists === true) {
    return { type: 'exists', header: rule.header }
  }

  if (typeof rule.header === 'string' && Array.isArray(rule.oneOf)) {
    return { type: 'oneOf', header: rule.header, oneOf: rule.oneOf }
  }

  if (typeof rule.headerNamePattern === 'string') {
    return {
      type: 'headerNamePattern',
      regex: createSafeRegExp(rule.headerNamePattern, rule.flags ?? '')
    }
  }

  return null
}

const compileTextPattern = rule => {
  if (typeof rule.contains === 'string') return rule.contains
  if (typeof rule.regex === 'string') {
    return createSafeRegExp(rule.regex, rule.flags ?? 'i')
  }
  return null
}

const compileRule = (detectionType, rule) => {
  if (!rule || typeof rule !== 'object') return () => false

  if (typeof rule.header === 'string' && typeof rule.equals === 'string') {
    return ({ getHeader }) => getHeader(rule.header) === rule.equals
  }

  if (typeof rule.header === 'string' && typeof rule.startsWith === 'string') {
    return ({ getHeader }) =>
      getHeader(rule.header)?.startsWith(rule.startsWith)
  }

  if (
    typeof rule.header === 'string' &&
    rule.exists === true &&
    typeof rule.except === 'string'
  ) {
    const except = rule.except.toLowerCase()
    return ({ getHeader }) => {
      const value = getHeader(rule.header)
      return Boolean(value) && String(value).toLowerCase() !== except
    }
  }

  if (typeof rule.header === 'string' && rule.exists === true) {
    return ({ getHeader }) => Boolean(getHeader(rule.header))
  }

  if (typeof rule.header === 'string' && Array.isArray(rule.oneOf)) {
    return ({ getHeader }) => rule.oneOf.includes(getHeader(rule.header))
  }

  if (typeof rule.headerNamePattern === 'string') {
    const regex = createSafeRegExp(rule.headerNamePattern, rule.flags ?? '')
    if (!regex) return () => false
    return ({ headerNames }) => headerNames.some(name => regex.test(name))
  }

  if (typeof rule.cookie === 'string') {
    return ({ hasCookie }) => hasCookie(rule.cookie)
  }

  if (typeof rule.contains === 'string') {
    if (detectionType === 'html') return ({ htmlHas }) => htmlHas(rule.contains)
    if (detectionType === 'url') return ({ urlHas }) => urlHas(rule.contains)
    return () => false
  }

  if (typeof rule.regex === 'string') {
    const regex = createSafeRegExp(rule.regex, rule.flags ?? 'i')
    if (!regex) return () => false
    if (detectionType === 'html') return ({ htmlHas }) => htmlHas(regex)
    if (detectionType === 'url') return ({ urlHas }) => urlHas(regex)
    return () => false
  }

  if (Number.isInteger(rule.status)) {
    return ({ statusCode }) => statusCode === rule.status
  }

  return () => false
}

const compileDetection = detection => {
  if (detection.type === 'cookies') {
    const cookiePatterns = detection.rules.map(rule => rule.cookie)
    return {
      type: detection.type,
      domain: detection.domain,
      matches: context => context.hasCookie(cookiePatterns)
    }
  }

  if (detection.type === 'html') {
    const patterns = detection.rules.map(compileTextPattern)
    return {
      type: detection.type,
      domain: detection.domain,
      matches: context => context.hasAnyHtml(patterns)
    }
  }

  if (detection.type === 'url') {
    const patterns = detection.rules.map(compileTextPattern)
    return {
      type: detection.type,
      domain: detection.domain,
      matches: context => context.hasAnyUrl(patterns)
    }
  }

  if (detection.type === 'headers') {
    const headerRules = detection.rules.map(compileHeaderRule)
    return {
      type: detection.type,
      domain: detection.domain,
      matches: context => context.hasAnyHeader(headerRules)
    }
  }

  if (detection.type === 'status_code') {
    const statusCodes = detection.rules.map(rule => rule.status)
    return {
      type: detection.type,
      domain: detection.domain,
      matches: context => context.hasAnyStatusCode(statusCodes)
    }
  }

  const rules = detection.rules.map(rule => compileRule(detection.type, rule))

  return {
    type: detection.type,
    domain: detection.domain,
    matches: context => rules.some(rule => rule(context))
  }
}

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
  const hasCookie = createHasCookie(headers)
  const htmlHas = createTestPattern(html)
  const urlHas = createTestPattern(url)
  const headerNames = getHeaderNames(headers)
  const hasAnyHtml = patterns =>
    patterns.some(pattern => pattern && htmlHas(pattern))
  const hasAnyUrl = patterns =>
    patterns.some(pattern => pattern && urlHas(pattern))
  const hasAnyStatusCode = statusCodes => statusCodes.includes(statusCode)
  const hasAnyHeader = headerRules =>
    headerRules.some(rule => {
      if (!rule) return false

      if (rule.type === 'equals') {
        return getHeader(rule.header) === rule.equals
      }

      if (rule.type === 'startsWith') {
        return getHeader(rule.header)?.startsWith(rule.startsWith)
      }

      if (rule.type === 'exists') {
        return Boolean(getHeader(rule.header))
      }

      if (rule.type === 'oneOf') {
        return rule.oneOf.includes(getHeader(rule.header))
      }

      if (rule.type === 'existsExcept') {
        const value = getHeader(rule.header)
        return Boolean(value) && String(value).toLowerCase() !== rule.except
      }

      if (rule.type === 'headerNamePattern') {
        return rule.regex
          ? headerNames.some(name => rule.regex.test(name))
          : false
      }

      return false
    })

  let domain
  const context = {
    getHeader,
    hasCookie,
    hasAnyHeader,
    htmlHas,
    hasAnyHtml,
    urlHas,
    hasAnyUrl,
    headerNames,
    statusCode,
    hasAnyStatusCode
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

const createDetector = providers => {
  const compiledProviders = compileProviders(providers)
  return input => {
    const { headers, html, body, url, statusCode, status } = input || {}
    return detectWithProviders(compiledProviders, {
      headers,
      html: html || body,
      url,
      statusCode: statusCode ?? status
    })
  }
}

const isAntibot = (input = {}) => {
  const { headers, html, body, url, statusCode, status } = input
  return detectWithProviders(COMPILED_PROVIDERS, {
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
module.exports.createDetector = createDetector
