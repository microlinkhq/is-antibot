'use strict'

const debug = require('debug-logfmt')('is-antibot')

const getHeader = (headers, name) =>
  typeof headers.get === 'function' ? headers.get(name) : headers[name]

module.exports = ({ headers = {} } = {}) => {
  let detected = false
  let provider = null

  // https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (getHeader(headers, 'cf-mitigated') === 'challenge') {
    detected = true
    provider = 'cloudflare'
  }

  // https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (getHeader(headers, 'x-vercel-mitigated') === 'challenge') {
    detected = true
    provider = 'vercel'
  }

  // https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (getHeader(headers, 'akamai-cache-status')?.startsWith('Error')) {
    detected = true
    provider = 'akamai'
  }

  // https://docs.datadome.co/reference/validate-request
  // 1: Soft challenge / JS redirect / interstitial
  // 2: Hard challenge / HTML redirect / CAPTCHA
  if (['1', '2'].includes(getHeader(headers, 'x-dd-b'))) {
    detected = true
    provider = 'datadome'
  }

  debug({ detected, provider })
  return { detected, provider }
}

module.exports.debug = debug
