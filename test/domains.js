'use strict'

const path = require('path')
const test = require('ava')

const { DOMAINS_FIXTURES, loadHAR } = require('./util')

const isAntibot = require('../src')

for (const domain of DOMAINS_FIXTURES) {
  test(path.basename(domain), async t => {
    const data = await loadHAR(domain)
    const result = isAntibot(data)
    t.is(result.detected, true)
    t.truthy(result.provider)
  })
}
