import isAntibot from 'is-antibot'

const response = await fetch('https://www.linkedin.com/in/kikobeats/')

const { headers, status: statusCode, url } = response

const { detected, provider, detection, technique } = isAntibot({
  headers,
  statusCode,
  html: await response.text(),
  url
})

if (detected) {
  console.log(`Blocked by ${provider} (via ${detection}, ${technique})`)
  // => "Blocked by linkedin (via statusCode, waf)"
}
