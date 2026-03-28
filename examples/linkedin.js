'use strict'

const got = require('got')

const isAntibot = require('../src')

const url = 'https://www.linkedin.com/in/kikobeats/'
const headers = { 'user-agent': 'curl/7.81.0' }

got(url, { headers, throwHttpErrors: false }).catch(error => {
  const response = error.response
  const headers = response.headers
  const html = response.body
  const result = isAntibot({ headers, html, url })

  console.log(`\n[ got version ]
  status: ${response.status}
detected: ${result.detected}
provider: ${result.provider}`)
})

fetch(url, { headers }).then(async response => {
  const headers = response.headers
  const html = await response.text()
  const result = isAntibot({ headers, html, url })

  console.log(`\n[ fetch version ]

  status: ${response.status}
detected: ${result.detected}
provider: ${result.provider}`)
})
