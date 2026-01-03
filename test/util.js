'use strict'

const { statSync, readdirSync } = require('fs')
const { readFile } = require('fs/promises')
const { load } = require('cheerio')
const path = require('path')

const DOMAINS_PATH = path.join(__dirname, '../domains')

const loadHAR = async filepath => {
  const har = await readFile(path.join(filepath, 'har.json'), 'utf8')
  const json = JSON.parse(har)
  const response = json.log.entries[0].response

  return {
    url: json.log.entries[0].request.url,
    headers: response.headers.reduce((acc, header) => {
      acc[header.name] = header.value
      return acc
    }, {}),
    statusCode: response.status,
    htmlDom: load(await readFile(path.join(filepath, 'index.html'), 'utf8'))
  }
}

const DOMAINS_FIXTURES = readdirSync(DOMAINS_PATH)
  .filter(file => statSync(path.join(DOMAINS_PATH, file)).isDirectory())
  .map(file => path.join(DOMAINS_PATH, file))

module.exports = { DOMAINS_FIXTURES, loadHAR }
