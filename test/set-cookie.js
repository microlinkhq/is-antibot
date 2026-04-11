'use strict'

const test = require('ava')

const { createHasCookie } = require('../src')

test('array (got-style)', t => {
  const hasCookie = createHasCookie({
    'set-cookie': ['foo=bar', 'trkCode=bf; Max-Age=5']
  })
  t.is(hasCookie('trkCode=bf'), true)
  t.is(hasCookie('foo=bar'), true)
  t.is(hasCookie('missing=value'), false)
})

test('comma-joined string (fetch-style)', t => {
  const hasCookie = createHasCookie({
    'set-cookie': 'foo=bar; Max-Age=5, trkCode=bf; Max-Age=5'
  })
  t.is(hasCookie('trkCode=bf'), true)
  t.is(hasCookie('foo=bar'), true)
  t.is(hasCookie('missing=value'), false)
})

test('single string', t => {
  const hasCookie = createHasCookie({ 'set-cookie': 'trkCode=bf; Max-Age=5' })
  t.is(hasCookie('trkCode=bf'), true)
  t.is(hasCookie('missing=value'), false)
})

test('Fetch Headers object', t => {
  const hasCookie = createHasCookie({
    get: () => 'foo=bar, trkCode=bf; Max-Age=5'
  })
  t.is(hasCookie('trkCode=bf'), true)
  t.is(hasCookie('missing=value'), false)
})

test('comma in Expires (no false split)', t => {
  const hasCookie = createHasCookie({
    'set-cookie': 'trkCode=bf; expires=Thu, 26-Mar-26 09:08:53 GMT; path=/'
  })
  t.is(hasCookie('trkCode=bf'), true)
})

test('no set-cookie header', t => {
  const hasCookie = createHasCookie({})
  t.is(hasCookie('trkCode=bf'), false)
})

test('undefined set-cookie', t => {
  const hasCookie = createHasCookie({ 'set-cookie': undefined })
  t.is(hasCookie('trkCode=bf'), false)
})

test('empty string', t => {
  const hasCookie = createHasCookie({ 'set-cookie': '' })
  t.is(hasCookie('trkCode=bf'), false)
})

test('empty array', t => {
  const hasCookie = createHasCookie({ 'set-cookie': [] })
  t.is(hasCookie('trkCode=bf'), false)
})

test('array patterns', t => {
  const hasCookie = createHasCookie({
    'set-cookie': ['foo=bar; path=/', 'trkCode=bf; Max-Age=5']
  })
  t.is(hasCookie(['missing=value', 'trkCode=bf']), true)
  t.is(hasCookie(['missing=value', 'another=value']), false)
})
