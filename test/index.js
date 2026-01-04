'use strict'

const { load } = require('cheerio')
const test = require('ava')

const isAntibot = require('../src')

test('cloudflare', t => {
  const url = 'https://example.com'
  const headers = { 'cf-mitigated': 'challenge' }
  const result = isAntibot({ url, headers, htmlDom: load('') })
  t.true(result)
})

test('vercel', t => {
  const url = 'https://example.com'
  const headers = { 'x-vercel-mitigated': 'challenge' }
  const result = isAntibot({ url, headers, htmlDom: load('') })
  t.true(result)
})

test('akamai', t => {
  const url = 'https://example.com'
  const headers = { 'akamai-cache-status': 'Error from child' }
  const result = isAntibot({ url, headers, htmlDom: load('') })
  t.true(result)
})

test('akamai (no antibot)', t => {
  const url = 'https://example.com'
  const headers = { 'akamai-cache-status': 'HIT' }
  const result = isAntibot({ url, headers, htmlDom: load('') })
  t.false(result)
})

test('datadome', t => {
  const url = 'https://example.com'
  for (const value of ['1', '2']) {
    const headers = { 'x-dd-b': value }
    const result = isAntibot({ url, headers, htmlDom: load('') })
    t.true(result, `should detect datadome for x-dd-b=${value}`)
  }
})

test('general (no antibot)', t => {
  const url = 'https://example.com'
  const result = isAntibot({ url, headers: {}, htmlDom: load('') })
  t.false(result)
})

test('no headers provided', t => {
  const url = 'https://example.com'
  const result = isAntibot({ url, htmlDom: load('') })
  t.false(result)
})
