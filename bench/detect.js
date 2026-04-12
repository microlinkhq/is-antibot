'use strict'

const { execSync } = require('child_process')
const { readFileSync } = require('fs')
const Module = require('module')
const path = require('path')

const PROVIDER_REQUIRE_PATTERNS = [
  "const providersData = require('./providers.json')",
  "const providersData = require('../providers/providers.json')"
]
const CWD = path.join(__dirname, '..')
const SRC_DIR = path.join(CWD, 'src')

const scenarios = [
  {
    name: 'cloudflare-header-hit',
    input: { headers: { 'cf-mitigated': 'challenge' } }
  },
  {
    name: 'no-match-empty-headers',
    input: { headers: {} }
  },
  {
    name: 'linkedin-status-domain-hit',
    input: { url: 'https://www.linkedin.com/in/a', statusCode: 999 }
  },
  {
    name: 'cookie-heavy-no-match',
    input: {
      headers: {
        'set-cookie':
          'foo=1; Path=/, bar=2; Path=/, baz=3; Path=/, qux=4; Path=/, other=5; Expires=Thu, 26-Mar-26 09:08:53 GMT; Path=/'
      },
      html: '',
      url: 'https://example.com'
    }
  },
  {
    name: 'cookie-late-match-aws-waf',
    input: {
      headers: {
        'set-cookie':
          'foo=1; Path=/, bar=2; Path=/, baz=3; Path=/, qux=4; Path=/, other=5; Expires=Thu, 26-Mar-26 09:08:53 GMT; Path=/, aws-waf-token=abc; Path=/'
      },
      html: '',
      url: 'https://example.com'
    }
  }
]

const median = values => {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.floor((sorted.length - 1) / 2)]
}

const sanitizeRef = ref => ref.replace(/[^a-zA-Z0-9_-]/g, '_')

const gitShow = (ref, file) =>
  execSync(`git show ${ref}:${file}`, {
    cwd: CWD,
    encoding: 'utf8'
  })

const maybeGitShow = (ref, file) => {
  try {
    return gitShow(ref, file)
  } catch {
    return null
  }
}

const loadDetectorFromRef = ref => {
  if (!ref || ref === 'local') {
    return require(path.join(CWD, 'src'))
  }

  let source = gitShow(ref, 'src/index.js')
  const providerRequirePattern = PROVIDER_REQUIRE_PATTERNS.find(pattern =>
    source.includes(pattern)
  )
  if (providerRequirePattern) {
    const providers =
      maybeGitShow(ref, 'src/providers.json') ||
      maybeGitShow(ref, 'providers/providers.json') ||
      readFileSync(path.join(CWD, 'src/providers.json'), 'utf8')
    source = source.replace(
      providerRequirePattern,
      `const providersData = ${providers}`
    )
  }

  const virtualFilename = path.join(SRC_DIR, `__bench_${sanitizeRef(ref)}.js`)
  const mod = new Module(virtualFilename, module)
  mod.filename = virtualFilename
  mod.paths = Module._nodeModulePaths(SRC_DIR)
  mod._compile(source, virtualFilename)
  return mod.exports
}

const bench = (detector, input, iterations, warmup) => {
  for (let i = 0; i < warmup; i++) detector(input)
  const start = process.hrtime.bigint()
  for (let i = 0; i < iterations; i++) detector(input)
  const end = process.hrtime.bigint()
  const totalNs = Number(end - start)
  const perOpNs = totalNs / iterations
  return {
    perOpUs: perOpNs / 1e3,
    opsSec: 1e9 / perOpNs
  }
}

const measureScenarios = (label, detector, rounds, iterations, warmup) =>
  scenarios.map(scenario => {
    const perOpUs = []
    const opsSec = []
    for (let i = 0; i < rounds; i++) {
      const result = bench(detector, scenario.input, iterations, warmup)
      perOpUs.push(result.perOpUs)
      opsSec.push(result.opsSec)
    }
    return {
      label,
      scenario: scenario.name,
      perOpUs: median(perOpUs),
      opsSec: median(opsSec)
    }
  })

const printSingle = results => {
  console.log('Scenario                             per_op_us     ops_sec')
  console.log('-----------------------------------------------------------')
  for (const row of results) {
    const name = row.scenario.padEnd(35, ' ')
    const us = row.perOpUs.toFixed(3).padStart(9, ' ')
    const ops = Math.round(row.opsSec).toString().padStart(11, ' ')
    console.log(`${name} ${us} ${ops}`)
  }
}

const printCompare = (leftLabel, rightLabel, leftRows, rightRows) => {
  const rightByScenario = Object.fromEntries(
    rightRows.map(row => [row.scenario, row])
  )

  console.log(
    `Scenario                             ${leftLabel}_us   ${rightLabel}_us   latency_delta`
  )
  console.log(
    '------------------------------------------------------------------------'
  )

  for (const leftRow of leftRows) {
    const rightRow = rightByScenario[leftRow.scenario]
    const delta = (leftRow.perOpUs / rightRow.perOpUs - 1) * 100
    const name = leftRow.scenario.padEnd(35, ' ')
    const left = leftRow.perOpUs.toFixed(3).padStart(9, ' ')
    const right = rightRow.perOpUs.toFixed(3).padStart(10, ' ')
    const pct = `${delta >= 0 ? '+' : ''}${delta.toFixed(2)}%`.padStart(12, ' ')
    console.log(`${name} ${left} ${right} ${pct}`)
  }
}

const main = () => {
  const [leftRef = 'local', rightRef] = process.argv.slice(2)
  const rounds = Number(process.env.BENCH_ROUNDS || 7)
  const iterations = Number(process.env.BENCH_ITERATIONS || 120000)
  const warmup = Number(process.env.BENCH_WARMUP || 20000)

  const leftDetector = loadDetectorFromRef(leftRef)
  const leftLabel = leftRef === 'local' ? 'local' : leftRef
  const leftResults = measureScenarios(
    leftLabel,
    leftDetector,
    rounds,
    iterations,
    warmup
  )

  if (!rightRef) {
    printSingle(leftResults)
    return
  }

  const rightDetector = loadDetectorFromRef(rightRef)
  const rightResults = measureScenarios(
    rightRef,
    rightDetector,
    rounds,
    iterations,
    warmup
  )
  printCompare(leftLabel, rightRef, leftResults, rightResults)
}

main()
