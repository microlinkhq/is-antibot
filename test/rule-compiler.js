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

test('statusCodes AND-gates detection', t => {
  const detect = createDetector({
    providers: [
      {
        name: 'gated',
        detections: [
          {
            type: 'headers',
            statusCodes: [500],
            rules: [{ header: 'x-cache', startsWith: 'Error' }]
          }
        ]
      }
    ]
  })

  t.is(
    detect({
      headers: { 'x-cache': 'Error from cloudfront' },
      statusCode: 500
    }).provider,
    'gated'
  )
  t.is(
    detect({
      headers: { 'x-cache': 'Error from cloudfront' },
      statusCode: 200
    }).detected,
    false
  )
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
  t.is(result.technique, null)
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

test('html contains matches the literal, including case and regex metacharacters', t => {
  const detect = createDetector({
    providers: [
      {
        name: 'literal',
        detections: [{ type: 'html', rules: [{ contains: 'A+B' }] }]
      }
    ]
  })

  t.is(detect({ html: 'prefix A+B suffix' }).provider, 'literal')
  t.is(detect({ html: 'prefix a+b suffix' }).provider, 'literal')
  t.false(detect({ html: 'prefix AB suffix' }).detected)
  t.false(detect({ html: 'prefix aXb suffix' }).detected)
})

test.serial(
  'html contains prefilter does not scan when no html literal is present',
  t => {
    const detect = createDetector({
      providers: [
        {
          name: 'markers',
          detections: [
            { type: 'html', rules: [{ contains: 'html-marker' }] },
            { type: 'url', rules: [{ contains: 'url-marker' }] }
          ]
        }
      ]
    })
    const html = 'a page that mentions url-marker only'
    const lowerHtml = html.toLowerCase()
    const original = String.prototype.indexOf
    let htmlScans = 0
    // eslint-disable-next-line no-extend-native
    String.prototype.indexOf = function (search, position) {
      if (String(this) === lowerHtml) htmlScans++
      return original.call(this, search, position)
    }
    let result
    try {
      result = detect({ html, url: 'https://example.com/nope' })
    } finally {
      // eslint-disable-next-line no-extend-native
      String.prototype.indexOf = original
    }

    // A url literal on the page must not count as an html literal. The screen
    // then skips indexOf. Deleting that skip, or folding url literals into it,
    // still returns no detection, so the scan count is the lock.
    t.false(result.detected)
    t.is(htmlScans, 0)
  }
)

test('document-wide html lookaheads match either order and scan forward', t => {
  const { providers } = require('../src/providers.json')
  const ruleFor = name => {
    const provider = providers.find(item => item.name === name)
    for (const detection of provider.detections) {
      for (const rule of detection.rules) {
        if (rule.regex && rule.regex.includes('[\\s\\S]*')) return rule
      }
    }
    return null
  }
  const cases = [
    {
      provider: 'perimeterx',
      yes: [
        'window._pxAppId <div id="px-captcha">',
        '<div id="px-captcha"></div> window._pxAppId',
        'WINDOW._PXAPPID PX-CAPTCHA'
      ],
      no: ['window._pxAppId', 'px-captcha', '<title>Robot or human?</title>']
    },
    {
      provider: 'recaptcha',
      yes: [' id="captcha-form" g-recaptcha', 'g-recaptcha id="captcha-form"'],
      no: [
        ' id="captcha-form"',
        'g-recaptcha',
        'class="captcha-form" g-recaptcha'
      ]
    },
    {
      provider: 'hcaptcha',
      yes: [
        'h-captcha Verify you are human',
        'Verify you are a human <div class="h-captcha">'
      ],
      no: [
        'h-captcha',
        'Verify you are human',
        'h-captcha-response Verify you are human'
      ]
    },
    {
      provider: 'funcaptcha',
      yes: [
        'arkoselabs.com enforcement.js',
        'enforcement.js https://arkoselabs.com/v2'
      ],
      no: ['arkoselabs.com', 'Attention Required']
    },
    {
      provider: 'cloudflare-turnstile',
      yes: [
        'cf-turnstile Just a moment',
        'Just a moment <div class="cf-turnstile">'
      ],
      no: ['cf-turnstile', 'Just a moment']
    },
    {
      provider: 'friendly-captcha',
      yes: [
        'frc-captcha Please verify',
        'Please verify <div class="frc-captcha">'
      ],
      no: ['frc-captcha', 'Please verify']
    },
    {
      provider: 'qcloud-captcha',
      yes: [
        'TencentCaptcha tcaptcha_transform',
        'tcaptcha_transform TencentCaptcha',
        'turing.captcha 请点击按钮开始验证'
      ],
      no: ['TencentCaptcha', '请点击按钮开始验证']
    },
    {
      provider: 'fullstory-challenge',
      yes: [
        '_fs-ch- <title>Client Challenge</title>',
        '<title>Client Challenge</title> _fs-ch-'
      ],
      no: ['_fs-ch-', '<title>Client Challenge</title>']
    }
  ]

  t.is(cases.length, 8)
  for (const item of cases) {
    const rule = ruleFor(item.provider)
    t.truthy(rule, item.provider)
    t.regex(rule.regex, /\[\\s\\S\]\*\?/)
    const pattern = new RegExp(rule.regex, rule.flags ?? '')
    for (const html of item.yes) {
      t.true(pattern.test(html), `${item.provider} ${html}`)
    }
    for (const html of item.no) {
      t.false(pattern.test(html), `${item.provider} ${html}`)
    }
  }
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
