'use strict'

const debug = require('debug-logfmt')('is-antibot')

module.exports = ({ url, htmlDom, headers = {} } = {}) => {
  // https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/
  if (headers['cf-mitigated'] === 'challenge') {
    debug({ provider: 'cloudflare' })
    return true
  }

  // https://github.com/glizzykingdreko/Vercel-Attack-Mode-Solver
  if (headers['x-vercel-mitigated'] === 'challenge') {
    debug({ provider: 'vercel' })
    return true
  }

  // https://techdocs.akamai.com/property-mgr/docs/return-cache-status
  if (headers['akamai-cache-status']?.startsWith('Error')) {
    debug({ provider: 'akamai' })
    return true
  }

  // https://docs.datadome.co/reference/validate-request
  // 1: Soft challenge / JS redirect / interstitial
  // 2: Hard challenge / HTML redirect / CAPTCHA
  if (['1', '2'].includes(headers['x-dd-b'])) {
    debug({ provider: 'datadome' })
    return true
  }

  return false
}

module.exports.debug = debug
