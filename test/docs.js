'use strict'

const test = require('ava')
const fs = require('fs')

const generate = require('../scripts/generate-docs')
const { providers } = require('../src/providers.json')

const SIGNAL = {
  headers: 'Headers',
  cookies: 'Cookies',
  html: 'HTML',
  url: 'URL',
  status_code: 'Status Code'
}

const parseRows = markup =>
  [
    ...markup.matchAll(
      /<tr><td>(.*?)<\/td><td>(.*?)<\/td><td>(\d+)<\/td><td>(.*?)<\/td><\/tr>/g
    )
  ].map(([, label, category, signals, chips]) => ({
    label,
    category,
    signals: Number(signals),
    methods: [
      ...chips.matchAll(/<span class="provider-chip">(.*?)<\/span>/g)
    ].map(([, method]) => method)
  }))

test('docs match providers.json', t => {
  for (const { file, content } of generate()) {
    t.is(
      fs.readFileSync(file, 'utf8'),
      content,
      `${file} is stale, run \`npm run docs\``
    )
  }
})

test('every provider has a row describing its real signals', t => {
  const rows = parseRows(generate.renderTable())
  t.is(rows.length, providers.length)

  for (const provider of providers) {
    const row = rows.find(({ label }) => label === provider.label)
    t.truthy(row, `${provider.name} is missing from the table`)

    const types = Object.keys(SIGNAL).filter(type =>
      provider.detections.some(detection => detection.type === type)
    )
    t.is(row.signals, types.length, `${provider.name} signal count`)
    t.deepEqual(
      row.methods,
      types.map(type => SIGNAL[type]),
      `${provider.name} detection methods`
    )
  }
})

test('table rows are sorted by label', t => {
  const labels = parseRows(generate.renderTable()).map(({ label }) =>
    label.toLowerCase()
  )
  t.deepEqual(labels, [...labels].sort())
})

test('llms.txt lists every provider exactly once', t => {
  const listed = ['antibot', 'captcha', 'platform']
    .flatMap(category => generate.renderList(category).split('\n'))
    .flatMap(line => line.replace(/^- /, '').split(', '))

  t.deepEqual([...listed].sort(), providers.map(({ label }) => label).sort())
})
