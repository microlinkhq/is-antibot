'use strict'

const { statSync, readdirSync } = require('fs')
const { readFile } = require('fs/promises')
const path = require('path')

const DOMAINS_PATH = path.join(__dirname, '../domains')

const loadHAR = async filepath => {
  const har = await readFile(path.join(filepath, 'har.json'), 'utf8')
  const json = JSON.parse(har)
  const response = json.log.entries[0].response

  return response.headers.reduce((acc, header) => {
    acc[header.name] = header.value
    return acc
  }, {})
}

const DOMAINS_FIXTURES = readdirSync(DOMAINS_PATH)
  .filter(file => statSync(path.join(DOMAINS_PATH, file)).isDirectory())
  .map(file => path.join(DOMAINS_PATH, file))

module.exports = { DOMAINS_FIXTURES, loadHAR }
