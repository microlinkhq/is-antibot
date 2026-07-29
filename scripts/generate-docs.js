'use strict'

const path = require('path')
const fs = require('fs')

const { providers } = require('../src/providers.json')

const DOCS = path.join(__dirname, '..', 'docs')

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

const generate = () => {
  const readme = path.join(DOCS, 'README.md')
  const llms = path.join(DOCS, 'llms.txt')

  const table = replaceBlock(
    fs.readFileSync(readme, 'utf8'),
    providersMarker,
    renderTable(),
    'the providers table markers in docs/README.md'
  )

  const lists = Object.entries(CATEGORY).reduce(
    (content, [category, { heading }]) =>
      replaceBlock(
        content,
        listMarker(heading),
        renderList(category),
        `"${heading}" in docs/llms.txt`
      ),
    fs.readFileSync(llms, 'utf8')
  )

  return [
    { file: readme, content: table },
    { file: llms, content: lists }
  ]
}

const relative = file => path.relative(path.join(__dirname, '..'), file)

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

if (require.main === module) main()
