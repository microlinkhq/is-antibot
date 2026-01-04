<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/microlinkhq/cdn/raw/master/dist/logo/banner-dark.png">
  <img alt="microlink cdn" src="https://github.com/microlinkhq/cdn/raw/master/dist/logo/banner.png" align="center">
</picture>

![Last version](https://img.shields.io/github/tag/microlinkhq/is-antibot.svg?style=flat-square)
[![Coverage Status](https://img.shields.io/coveralls/microlinkhq/is-antibot.svg?style=flat-square)](https://coveralls.io/github/microlinkhq/is-antibot)
[![NPM Status](https://img.shields.io/npm/dm/is-antibot.svg?style=flat-square)](https://www.npmjs.org/package/is-antibot)

> Identify if a response is an antibot challenge from CloudFlare, Akamai, DataDome, Vercel, and more.

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

## License

**is-antibot** © [microlink.io](https://microlink.io), released under the [MIT](https://github.com/microlinkhq/is-antibot/blob/master/LICENSE.md) License.<br>
Authored and maintained by [microlink.io](https://microlink.io) with help from [contributors](https://github.com/microlinkhq/is-antibot/contributors).

> [microlink.io](https://microlink.io) · GitHub [microlink.io](https://github.com/microlinkhq) · X [@microlinkhq](https://x.com/microlinkhq)
