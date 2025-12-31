'use strict'

const { parseUrl } = require('@metascraper/helpers')
const debug = require('debug-logfmt')('is-antibot')

module.exports = ({ url, htmlDom, html, headers = {} } = {}) => {
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

  const { domainWithoutSuffix } = parseUrl(url)

  if (domainWithoutSuffix === 'reddit') {
    const condition = htmlDom.text().includes('Prove your humanity')
    if (condition) {
      debug({ provider: 'reddit' })
      return true
    }
  }

  return false
}
