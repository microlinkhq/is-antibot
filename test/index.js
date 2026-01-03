'use strict'

const { load } = require('cheerio')
const test = require('ava')
const path = require('path')

const isCaptcha = require('../src')

const { DOMAINS_FIXTURES, loadHAR } = require('./util')

for (const domain of DOMAINS_FIXTURES) {
  test(path.basename(domain), async t => {
    const data = await loadHAR(domain)
    t.true(isCaptcha(data))
  })
}

test('cloudflare', t => {
  const url = 'https://example.com'
  const headers = { 'cf-mitigated': 'challenge' }
  const result = isCaptcha({ url, headers, htmlDom: load('') })
  t.true(result)
})

test('vercel', t => {
  const url = 'https://example.com'
  const headers = { 'x-vercel-mitigated': 'challenge' }
  const result = isCaptcha({ url, headers, htmlDom: load('') })
  t.true(result)
})

test('akamai', t => {
  const url = 'https://example.com'
  const headers = { 'akamai-cache-status': 'Error from child' }
  const result = isCaptcha({ url, headers, htmlDom: load('') })
  t.true(result)
})

test('akamai (no antibot)', t => {
  const url = 'https://example.com'
  const headers = { 'akamai-cache-status': 'HIT' }
  const result = isCaptcha({ url, headers, htmlDom: load('') })
  t.false(result)
})

test('reddit (no antibot)', t => {
  const url = 'https://reddit.com'
  const html = '<title>Reddit: the front page of the internet</title>'
  const result = isCaptcha({ url, htmlDom: load(html), headers: {} })
  t.false(result)
})

test('general (no antibot)', t => {
  const url = 'https://example.com'
  const result = isCaptcha({ url, headers: {}, htmlDom: load('') })
  t.false(result)
})

test('no headers provided', t => {
  const url = 'https://example.com'
  const result = isCaptcha({ url, htmlDom: load('') })
  t.false(result)
})

test('provide cheerio instance', t => {
  const url = 'https://reddit.com'
  const html = '<title>Prove your humanity</title>'
  const result = isCaptcha({ url, htmlDom: load(html) })
  t.true(result)
})
