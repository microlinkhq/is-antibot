<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/microlinkhq/cdn/raw/master/dist/logo/banner-dark.png">
  <img alt="microlink cdn" src="https://github.com/microlinkhq/cdn/raw/master/dist/logo/banner.png" align="center">
</picture>

![Last version](https://img.shields.io/github/tag/microlinkhq/is-antibot.svg?style=flat-square)
[![Coverage Status](https://img.shields.io/coveralls/microlinkhq/is-antibot.svg?style=flat-square)](https://coveralls.io/github/microlinkhq/is-antibot)
[![NPM Status](https://img.shields.io/npm/dm/is-antibot.svg?style=flat-square)](https://www.npmjs.org/package/is-antibot)

> Identify if a response is an antibot challenge from CloudFlare, Akamai, DataDome, Vercel, and more.

## Supported Providers

### Anti-Bot Systems

- **CloudFlare** - Bot management and challenge pages
- **Vercel** - Attack mode protection
- **Akamai** - Bot Manager and Web Application Protector
- **DataDome** - Bot protection with CAPTCHA challenges
- **PerimeterX** - Behavioral bot detection
- **Shape Security** - Enterprise bot management
- **Kasada** - Advanced bot mitigation
- **Imperva/Incapsula** - Web application firewall
- **AWS WAF** - Amazon Web Services Web Application Firewall

### CAPTCHA Providers

- **reCAPTCHA** - Google's CAPTCHA service (v2 and v3)
- **hCaptcha** - Privacy-focused CAPTCHA alternative
- **FunCaptcha** - Arkose Labs interactive challenges
- **GeeTest** - AI-powered CAPTCHA
- **Cloudflare Turnstile** - Privacy-preserving CAPTCHA alternative

## Why

Websites receiving massive quantities of traffic throughout the day, like LinkedIn, Instagram, or YouTube, have sophisticated antibot systems to prevent automated access.

When you try to fetch the HTML of these sites without the right tools, you often hit a 403 Forbidden, 429 Too Many Requests, or a "Please prove you're human" challenge, leaving you with a response that contains no useful data.

**is-antibot** is a lightweight, vendor-agnostic JavaScript library that identifies when a response is actually an antibot challenge, helping you understand when and why your request was blocked.

## Install

```bash
$ npm install is-antibot --save
```

## Usage

The library is designed for evaluating a HTTP response:

```js
const isAntibot = require('is-antibot')

const response = await fetch('https://example.com')
const { detected, provider } = isAntibot(response)

if (detected) {
  console.log(`Antibot detected: ${provider}`)
}
```

The library expects a [Fetch Response](https://developer.mozilla.org/en-US/docs/Web/API/Response) object, a [Node.js Response](https://nodejs.org/api/http.html#class-httpincomingmessage) object, or an object representing HTTP response headers as input.

You can also pass optional `body` and `url` parameters for enhanced detection:

```js
const result = isAntibot({
  headers: response.headers,
  body: await response.text(),
  url: response.url
})
```

### Response

The library returns an object with the following properties:

- `detected` (boolean): Whether an antibot challenge was detected
- `provider` (string|null): The name of the detected provider (e.g., 'cloudflare', 'recaptcha')

## License

**is-antibot** © [microlink.io](https://microlink.io), released under the [MIT](https://github.com/microlinkhq/is-antibot/blob/master/LICENSE.md) License.<br>
Authored and maintained by [microlink.io](https://microlink.io) with help from [contributors](https://github.com/microlinkhq/is-antibot/contributors).

> [microlink.io](https://microlink.io) · GitHub [microlink.io](https://github.com/microlinkhq) · X [@microlinkhq](https://x.com/microlinkhq)
