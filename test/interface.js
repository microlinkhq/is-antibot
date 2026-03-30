'use strict'

const test = require('ava')
const got = require('got')

const isAntibot = require('../src')

const url = 'https://www.linkedin.com/in/kikobeats/'
const headers = { 'user-agent': 'curl/7.81.0' }

test('from fetch', async t => {
  const response = await fetch(url, { headers })
  const html = await response.text()
  const { detected, provider, detection } = isAntibot({
    headers: response.headers,
    html,
    url: response.url
  })
  t.is(detected, true)
  t.is(provider, 'linkedin')
  t.true(['headers', 'cookies', 'html', 'url'].includes(detection))
})

test('from got', async t => {
  const response = await got(url, { headers }).catch(error => error.response)
  const { detected, provider, detection } = isAntibot(response)
  t.is(detected, true)
  t.is(provider, 'linkedin')
  t.true(['headers', 'cookies', 'html', 'url'].includes(detection))
})
