'use strict'

const test = require('ava')
const fs = require('fs')

const generate = require('../scripts/generate-docs')
const { $defs } = require('../src/schema.json')
const { providers } = require('../src/providers.json')
const { dependencies } = require('../package.json')

const WORD = ['zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven']

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

test('no surface states a count that contradicts the source', t => {
  const expected = {
    providers: `${Math.floor(providers.length / 10) * 10}+`,
    signals: WORD[$defs.detection.properties.type.enum.length],
    dependencies: String(Object.keys(dependencies).length)
  }

  const CLAIMS = [
    [/\b(\d+\+)(?: antibot)? providers\b/g, expected.providers],
    [/\b([A-Z][a-z]+) detection signals\b/g, expected.signals],
    [/\bonly (\d+) dependencies\b/g, expected.dependencies]
  ]

  const found = generate().flatMap(({ file }) => {
    const content = fs.readFileSync(file, 'utf8')
    return CLAIMS.flatMap(([pattern, value]) =>
      [...content.matchAll(pattern)].map(([match, stated]) => {
        t.is(stated, value, `${file}: "${match}"`)
        return match
      })
    )
  })

  t.true(found.length > 0, 'no claims found, the patterns went stale')
})

test('the advertised count never undersells the catalog', t => {
  for (let count = 0; count <= 120; count++) {
    const advertised = generate.roundDown(count)
    t.true(advertised <= count, `${advertised}+ overstates ${count} providers`)
    t.true(
      count === 0 || advertised > 0,
      `${count} providers must not advertise as 0+`
    )
  }

  t.is(generate.roundDown(9), 9)
  t.is(generate.roundDown(10), 10)
  t.is(generate.roundDown(36), 30)
  t.is(generate.roundDown(41), 40)
})

test('a category losing its last provider stays regenerable', t => {
  const heading = 'Detected CAPTCHA providers:'
  const marker = generate.listMarker(heading)
  const section = `${heading}\n\n- reCAPTCHA, hCaptcha\n\nNext:\n`

  const emptied = generate.replaceBlock(section, marker, '', heading)
  t.is(emptied, `${heading}\n\n\nNext:\n`)
  t.is(generate.replaceBlock(emptied, marker, '', heading), emptied)

  t.is(
    generate.replaceBlock(emptied, marker, '- GeeTest', heading),
    `${heading}\n\n- GeeTest\n\nNext:\n`
  )
})

test('llms.txt lists every provider exactly once', t => {
  const listed = ['antibot', 'captcha', 'platform']
    .flatMap(category => generate.renderList(category).split('\n'))
    .flatMap(line => line.replace(/^- /, '').split(', '))

  t.deepEqual([...listed].sort(), providers.map(({ label }) => label).sort())
})
