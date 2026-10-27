'use strict'

const { writeFileSync } = require('fs')
const { join } = require('path')

const { loadFixture } = require('../test/util')
const isAntibot = require('../src')

const RUNS = 7
const SEED = 0x5eed
const CLEAN_PAGE_BYTES = 200_000

const PROVIDERS = join(__dirname, '..', 'providers')

const WORDS = [
  'lorem',
  'ipsum',
  'dolor',
  'sit',
  'amet',
  'consectetur',
  'adipiscing',
  'elit',
  'sed',
  'tempor',
  'incididunt',
  'labore',
  'magna',
  'aliqua',
  'veniam',
  'nostrud',
  'exercitation',
  'ullamco',
  'laboris',
  'commodo'
]

const median = values => {
  const sorted = values.slice().sort((a, b) => a - b)
  return sorted[Math.floor(sorted.length / 2)]
}

const createRandom = seed => {
  let state = seed
  return () => {
    state = (state * 1103515245 + 12345) % 2147483648
    return state / 2147483648
  }
}

const createCleanPage = bytes => {
  const random = createRandom(SEED)
  const word = () => WORDS[Math.floor(random() * WORDS.length)]
  const sentence = length => Array.from({ length }, word).join(' ')
  const blocks = []
  let size = 0
  for (let index = 0; size < bytes; index++) {
    const block =
      `<section id="s${index}"><h2>${sentence(4)}</h2>` +
      `<p class="copy">${sentence(40)} <a href="/article/${index}">${sentence(
        3
      )}</a></p>` +
      `<img src="/static/${index}.jpg" alt="${sentence(3)}">` +
      `<script>window.__state${index} = { id: ${index}, label: "${word()}" }</script></section>\n`
    blocks.push(block)
    size += block.length
  }
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<title>Clean page</title><meta property="og:title" content="Clean page">' +
    `</head><body>${blocks.join('')}</body></html>`
  )
}

const workOf = input =>
  input.html ? `${input.html.length} html chars` : 'no html'

const sample = (input, iterations, expected) => {
  let detected
  for (let i = 0; i < iterations; i++) detected = isAntibot(input).detected
  if (detected !== expected) {
    throw new Error(`expected detected ${expected}, got ${detected}`)
  }
}

const measure = entry => {
  const walls = []
  let errors = 0
  sample(entry.input, 1, entry.expected)
  for (let run = 0; run < RUNS; run++) {
    const started = process.hrtime.bigint()
    try {
      sample(entry.input, entry.iterations, entry.expected)
      walls.push(Number(process.hrtime.bigint() - started) / 1e6)
    } catch (error) {
      errors++
      console.error(`${entry.name} run ${run}`, error)
    }
  }
  return { walls, errors }
}

const fmt = value => value.toFixed(1)

const report = (entry, { walls, errors }) => {
  const med = walls.length ? median(walls) : Number.NaN
  const min = walls.length ? Math.min(...walls) : Number.NaN
  const max = walls.length ? Math.max(...walls) : Number.NaN
  const extra =
    `work ${entry.iterations} calls, ${workOf(entry.input)}, ` +
    `detected ${entry.expected}, errors ${errors}, runs ${RUNS}`
  console.log(
    `${entry.name}  median ${fmt(med)}ms  range ${fmt(min)}-${fmt(
      max
    )}  ${extra}`
  )
  return {
    name: entry.name,
    unit: 'ms',
    value: Number(fmt(med)),
    range: `${fmt(min)}-${fmt(max)}`,
    extra
  }
}

const createCases = async () => [
  {
    name: 'imperva fixture html',
    input: await loadFixture(join(PROVIDERS, 'imperva', 'success.json')),
    iterations: 64,
    expected: false
  },
  {
    name: 'clean synthetic html',
    input: {
      url: 'https://example.com/article',
      statusCode: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      html: createCleanPage(CLEAN_PAGE_BYTES)
    },
    iterations: 64,
    expected: false
  },
  {
    name: 'linkedin fixture headers',
    input: await loadFixture(join(PROVIDERS, 'linkedin', 'success.json')),
    iterations: 20_000,
    expected: false
  },
  {
    name: 'headers only set-cookie',
    input: {
      statusCode: 403,
      headers: {
        'set-cookie':
          'foo=1; Path=/, bar=2; Path=/, baz=3; Path=/, qux=4; Path=/, other=5; Expires=Thu, 26-Mar-26 09:08:53 GMT; Path=/, aws-waf-token=abc; Path=/'
      }
    },
    iterations: 50_000,
    expected: true
  },
  {
    name: 'url gated walmart',
    input: {
      url: 'https://www.walmart.com/blocked?url=L2lwL3Rlc3Q&uuid=1',
      statusCode: 200,
      headers: {}
    },
    iterations: 100_000,
    expected: true
  }
]

const main = async () => {
  const results = []
  let errors = 0
  for (const entry of await createCases()) {
    let measured
    try {
      measured = measure(entry)
    } catch (error) {
      console.error(`${entry.name} warmup`, error)
      measured = { walls: [], errors: 1 }
    }
    errors += measured.errors
    results.push(report(entry, measured))
  }
  writeFileSync(
    join(__dirname, '..', 'benchmark-output.json'),
    JSON.stringify(results, null, 2) + '\n'
  )
  if (errors > 0 || results.some(result => !Number.isFinite(result.value))) {
    process.exitCode = 1
  }
}

main().catch(error => {
  console.error(error)
  process.exit(1)
})
