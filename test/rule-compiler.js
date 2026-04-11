'use strict'

const test = require('ava')

const { createDetector } = require('../src')

test('supports header operators', t => {
  const detect = createDetector({
    providers: [
      {
        name: 'test',
        detections: [
          {
            type: 'headers',
            rules: [
              { header: 'x-equals', equals: 'yes' },
              { header: 'x-prefix', startsWith: 'Error' },
              { header: 'x-exists', exists: true },
              { header: 'x-one-of', oneOf: ['a', 'b'] },
              { header: 'x-except', exists: true, except: 'protected' },
              { headerNamePattern: '^x-[a-z0-9]{8}-[abcdfz]$', flags: 'i' }
            ]
          }
        ]
      }
    ]
  })

  t.is(detect({ headers: { 'x-equals': 'yes' } }).provider, 'test')
  t.is(detect({ headers: { 'x-prefix': 'Error from edge' } }).provider, 'test')
  t.is(detect({ headers: { 'x-exists': '1' } }).provider, 'test')
  t.is(detect({ headers: { 'x-one-of': 'b' } }).provider, 'test')
  t.is(detect({ headers: { 'x-except': 'challenge' } }).provider, 'test')
  t.is(detect({ headers: { 'x-except': 'PROTECTED' } }).detected, false)
  t.is(detect({ headers: { 'x-abc12345-a': '1' } }).provider, 'test')
})

test('supports cookie, contains, regex, and status operators', t => {
  const detect = createDetector({
    providers: [
      {
        name: 'cookies',
        detections: [{ type: 'cookies', rules: [{ cookie: 'token=' }] }]
      },
      {
        name: 'html-contains',
        detections: [
          { type: 'html', rules: [{ contains: 'challenge marker' }] }
        ]
      },
      {
        name: 'url-regex',
        detections: [
          { type: 'url', rules: [{ regex: 'example\\.com\\/X', flags: 'i' }] }
        ]
      },
      {
        name: 'status',
        detections: [{ type: 'status_code', rules: [{ status: 451 }] }]
      }
    ]
  })

  t.is(
    detect({ headers: { 'set-cookie': 'token=abc123; Path=/' } }).provider,
    'cookies'
  )
  t.is(detect({ html: 'CHALLENGE MARKER' }).provider, 'html-contains')
  t.is(detect({ url: 'https://example.com/x' }).provider, 'url-regex')
  t.is(detect({ statusCode: 451 }).provider, 'status')
  t.is(detect({ statusCode: 451 }).detection, 'statusCode')
})

test('provider and detection order determines precedence', t => {
  const detect = createDetector({
    providers: [
      {
        name: 'first-provider',
        detections: [
          { type: 'url', rules: [{ contains: 'overlap' }] },
          { type: 'html', rules: [{ contains: 'overlap' }] }
        ]
      },
      {
        name: 'second-provider',
        detections: [{ type: 'html', rules: [{ contains: 'overlap' }] }]
      }
    ]
  })

  const result = detect({
    url: 'https://example.com/overlap',
    html: '<p>overlap</p>'
  })

  t.is(result.provider, 'first-provider')
  t.is(result.detection, 'url')
})

test('regex flags honors explicit empty string and defaults to i when omitted', t => {
  const explicitFlags = createDetector({
    providers: [
      {
        name: 'explicit',
        detections: [{ type: 'html', rules: [{ regex: 'abc', flags: '' }] }]
      }
    ]
  })

  t.is(explicitFlags({ html: 'ABC' }).detected, false)
  t.is(explicitFlags({ html: 'abc' }).provider, 'explicit')

  const defaultFlags = createDetector({
    providers: [
      {
        name: 'default',
        detections: [{ type: 'html', rules: [{ regex: 'abc' }] }]
      }
    ]
  })

  t.is(defaultFlags({ html: 'ABC' }).provider, 'default')
})

test('throws for invalid header rule shape', t => {
  const error = t.throws(() =>
    createDetector({
      providers: [
        {
          name: 'invalid-header-rule',
          detections: [{ type: 'headers', rules: [{ header: 'x-foo' }] }]
        }
      ]
    })
  )

  t.regex(error.message, /Invalid header rule shape/)
})
