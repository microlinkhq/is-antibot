'use strict'

const test = require('ava')
const got = require('got')

const isAntibot = require('../src')

const url = 'https://www.linkedin.com/in/kikobeats/'
const headers = { 'user-agent': 'curl/7.81.0' }

test('from fetch', async t => {
  const response = await fetch(url, { headers })
  const { detected, provider } = await isAntibot(response)
  t.is(detected, true)
  t.is(provider, 'linkedin')
  t.is(response.bodyUsed, false)
  const html = await response.text()
  t.true(html.length > 0)
})

test('from got', async t => {
  const response = await got(url, { headers }).catch(error => error.response)
  const { detected, provider } = isAntibot(response)
  t.is(detected, true)
  t.is(provider, 'linkedin')
})
