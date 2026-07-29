'use strict'

const path = require('path')
const fs = require('fs')

const { $defs } = require('../src/schema.json')
const { providers } = require('../src/providers.json')
const { dependencies } = require('../package.json')

const ROOT = path.join(__dirname, '..')
const DOCS = path.join(ROOT, 'docs')

const CATEGORY = {
  antibot: { label: 'Antibot', heading: 'Detected antibot systems:' },
  captcha: { label: 'CAPTCHA', heading: 'Detected CAPTCHA providers:' },
  platform: {
    label: 'Platform-specific',
    heading: 'Detected platform-specific protections:'
  }
}

const SIGNAL = {
  headers: 'Headers',
  cookies: 'Cookies',
  html: 'HTML',
  url: 'URL',
  status_code: 'Status Code'
}

const signalsOf = ({ detections }) =>
  Object.keys(SIGNAL).filter(type =>
    detections.some(detection => detection.type === type)
  )

const byLabel = (one, other) =>
  one.label.toLowerCase() < other.label.toLowerCase() ? -1 : 1

const escapeHtml = value =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

const renderRow = provider => {
  const signals = signalsOf(provider)
  const chips = signals
    .map(type => `<span class="provider-chip">${SIGNAL[type]}</span>`)
    .join('')

  return `      <tr><td>${escapeHtml(provider.label)}</td><td>${
    CATEGORY[provider.category].label
  }</td><td>${signals.length}</td><td>${chips}</td></tr>`
}

const renderTable = () => [...providers].sort(byLabel).map(renderRow).join('\n')

const renderList = (category, width = 74) =>
  providers
    .filter(provider => provider.category === category)
    .map(provider => provider.label)
    .reduce((lines, label) => {
      const last = lines[lines.length - 1]
      if (last && `${last}, ${label}`.length <= width) {
        lines[lines.length - 1] = `${last}, ${label}`
      } else lines.push(`- ${label}`)
      return lines
    }, [])
    .join('\n')

const NUMBER = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven']

const spell = count =>
  count < NUMBER.length
    ? NUMBER[count].replace(/^./, first => first.toUpperCase())
    : String(count)

const roundDown = count => Math.floor(count / 10) * 10

const claims = () => {
  const signals = spell($defs.detection.properties.type.enum.length)
  const covered = `${roundDown(providers.length)}+`

  return [
    [/\b\d+\+ antibot providers\b/g, `${covered} antibot providers`],
    [/\b\d+\+ providers\b/g, `${covered} providers`],
    [
      /\b(?:[A-Z][a-z]+|\d+) detection signals\b/g,
      `${signals} detection signals`
    ],
    [
      /\bonly \d+ dependencies\b/g,
      `only ${Object.keys(dependencies).length} dependencies`
    ]
  ]
}

const applyClaims = content =>
  claims().reduce(
    (updated, [pattern, value]) => updated.replace(pattern, value),
    content
  )

const replaceBlock = (content, pattern, block, hint) => {
  if (!pattern.test(content)) {
    throw new Error(`Cannot locate ${hint}: docs and generator are out of sync`)
  }
  return content.replace(pattern, (match, open) => `${open}${block}\n`)
}

const providersMarker =
  /(<!-- providers:start -->\n)[\s\S]*?(?= *<!-- providers:end -->)/

const listMarker = heading =>
  new RegExp(
    `(${heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n\\n)(?:- .*\\n)+`
  )

const withTable = content =>
  replaceBlock(
    content,
    providersMarker,
    renderTable(),
    'the providers table markers in docs/README.md'
  )

const withLists = content =>
  Object.entries(CATEGORY).reduce(
    (updated, [category, { heading }]) =>
      replaceBlock(
        updated,
        listMarker(heading),
        renderList(category),
        `"${heading}" in docs/llms.txt`
      ),
    content
  )

const TARGETS = [
  { file: path.join(DOCS, 'README.md'), render: withTable },
  { file: path.join(DOCS, 'llms.txt'), render: withLists },
  { file: path.join(DOCS, 'index.html'), render: content => content },
  { file: path.join(ROOT, 'package.json'), render: content => content }
]

const generate = () =>
  TARGETS.map(({ file, render }) => ({
    file,
    content: applyClaims(render(fs.readFileSync(file, 'utf8')))
  }))

const relative = file => path.relative(ROOT, file)

const main = () => {
  const check = process.argv.includes('--check')
  const results = generate()
  const stale = results.filter(
    ({ file, content }) => fs.readFileSync(file, 'utf8') !== content
  )

  if (!check) {
    stale.forEach(({ file, content }) => fs.writeFileSync(file, content))
    console.log(
      stale.length === 0
        ? `${providers.length} providers, docs already up to date`
        : `${providers.length} providers written to ${stale
          .map(({ file }) => relative(file))
          .join(', ')}`
    )
    return
  }

  if (stale.length === 0) return console.log('docs are up to date')

  console.error(
    `docs are stale, run \`npm run docs\`:\n${stale
      .map(({ file }) => `  ${relative(file)}`)
      .join('\n')}`
  )
  process.exitCode = 1
}

module.exports = generate
module.exports.renderTable = renderTable
module.exports.renderList = renderList
module.exports.claims = claims

if (require.main === module) main()
