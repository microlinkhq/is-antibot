'use strict'

const { statSync, readdirSync, existsSync } = require('fs')
const { readFile } = require('fs/promises')
const path = require('path')

const PROVIDERS_PATH = path.join(__dirname, '../providers')

const headersFromHAR = response =>
  response.headers.reduce((acc, header) => {
    const existing = acc[header.name]
    if (existing !== undefined) {
      acc[header.name] = Array.isArray(existing)
        ? [...existing, header.value]
        : [existing, header.value]
    } else {
      acc[header.name] = header.value
    }
    return acc
  }, {})

const loadFixture = async filepath => {
  const raw = await readFile(filepath, 'utf8')
  const json = JSON.parse(raw)
  const response = json.log.entries[0].response
  return {
    headers: headersFromHAR(response),
    statusCode: response.status,
    html: response.content?.text || '',
    url: json.log.entries[0].request?.url || ''
  }
}

const PROVIDER_FIXTURES = readdirSync(PROVIDERS_PATH)
  .filter(file => statSync(path.join(PROVIDERS_PATH, file)).isDirectory())
  .reduce(
    (acc, name) => {
      const dir = path.join(PROVIDERS_PATH, name)
      const failed = path.join(dir, 'failed.json')
      const success = path.join(dir, 'success.json')
      if (existsSync(failed)) acc.failed.push({ name, path: failed })
      if (existsSync(success)) acc.success.push({ name, path: success })
      return acc
    },
    { failed: [], success: [] }
  )

module.exports = { PROVIDER_FIXTURES, loadFixture }
