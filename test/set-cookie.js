'use strict'

const test = require('ava')

const { testSetCookie } = require('../src')

test('array (got-style)', t => {
  const headers = { 'set-cookie': ['foo=bar', 'trkCode=bf; Max-Age=5'] }
  t.is(testSetCookie(headers, 'trkCode=bf'), true)
  t.is(testSetCookie(headers, 'foo=bar'), true)
  t.is(testSetCookie(headers, 'missing=value'), false)
})

test('comma-joined string (fetch-style)', t => {
  const headers = { 'set-cookie': 'foo=bar; Max-Age=5, trkCode=bf; Max-Age=5' }
  t.is(testSetCookie(headers, 'trkCode=bf'), true)
  t.is(testSetCookie(headers, 'foo=bar'), true)
  t.is(testSetCookie(headers, 'missing=value'), false)
})

test('single string', t => {
  const headers = { 'set-cookie': 'trkCode=bf; Max-Age=5' }
  t.is(testSetCookie(headers, 'trkCode=bf'), true)
  t.is(testSetCookie(headers, 'missing=value'), false)
})

test('Fetch Headers object', t => {
  const headers = {
    get: () => 'foo=bar, trkCode=bf; Max-Age=5'
  }
  t.is(testSetCookie(headers, 'trkCode=bf'), true)
  t.is(testSetCookie(headers, 'missing=value'), false)
})

test('comma in Expires (no false split)', t => {
  const headers = {
    'set-cookie': 'trkCode=bf; expires=Thu, 26-Mar-26 09:08:53 GMT; path=/'
  }
  t.is(testSetCookie(headers, 'trkCode=bf'), true)
})

test('no set-cookie header', t => {
  t.is(testSetCookie({}, 'trkCode=bf'), false)
})

test('undefined set-cookie', t => {
  t.is(testSetCookie({ 'set-cookie': undefined }, 'trkCode=bf'), false)
})

test('empty string', t => {
  t.is(testSetCookie({ 'set-cookie': '' }, 'trkCode=bf'), false)
})

test('empty array', t => {
  t.is(testSetCookie({ 'set-cookie': [] }, 'trkCode=bf'), false)
})
