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
  let cookies
  const getCookies = () => {
    if (cookies === undefined) {
      cookies = splitSetCookieString(getHeader('set-cookie'))
    }
    return cookies
  }

  return patterns => {
    const parsedCookies = getCookies()
    if (Array.isArray(patterns)) {
      return parsedCookies.some(cookie =>
        patterns.some(pattern => cookie.startsWith(pattern))
      )
    }
    return parsedCookies.some(cookie => cookie.startsWith(patterns))
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
    return { type: 'oneOf', header: rule.header, oneOf: new Set(rule.oneOf) }
  }

  if (typeof rule.headerNamePattern === 'string') {
    return {
      type: 'headerNamePattern',
      regex: createRegExp(rule.headerNamePattern, rule.flags ?? '')
    }
  }
}

const compileTextPattern = rule => {
  if (typeof rule.contains === 'string') return rule.contains
  return createRegExp(rule.regex, rule.flags ?? 'i')
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
  const hasAnyHtml = patterns => patterns.some(pattern => htmlHas(pattern))
  const hasAnyUrl = patterns => patterns.some(pattern => urlHas(pattern))
  const hasAnyStatusCode = statusCodes => statusCodes.includes(statusCode)
  const hasAnyHeader = headerRules =>
    headerRules.some(rule => {
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
        return rule.oneOf.has(getHeader(rule.header))
      }

      if (rule.type === 'existsExcept') {
        const value = getHeader(rule.header)
        return Boolean(value) && String(value).toLowerCase() !== rule.except
      }

      if (rule.type === 'headerNamePattern') {
        return headerNames().some(name => rule.regex.test(name))
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
