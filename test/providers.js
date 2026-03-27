'use strict'

const test = require('ava')

const { PROVIDER_FIXTURES, loadFixture } = require('./util')

const isAntibot = require('../src')

test('true', async t => {
  for (const { name, path: fixturePath } of PROVIDER_FIXTURES.failed) {
    const fixture = await loadFixture(fixturePath)
    const result = isAntibot(fixture)
    t.is(result.detected, true, `Failed ${name}`)
    t.truthy(result.provider, `Failed ${name}`)
  }
})

test('false', async t => {
  for (const { name, path: fixturePath } of PROVIDER_FIXTURES.success) {
    const fixture = await loadFixture(fixturePath)
    const result = isAntibot(fixture)
    t.is(result.detected, false, `Failed ${name}`)
    t.is(result.provider, null, `Failed ${name}`)
  }
})
