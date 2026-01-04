<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/microlinkhq/cdn/raw/master/dist/logo/banner-dark.png">
  <img alt="microlink cdn" src="https://github.com/microlinkhq/cdn/raw/master/dist/logo/banner.png" align="center">
</picture>

![Last version](https://img.shields.io/github/tag/microlinkhq/is-antibot.svg?style=flat-square)
[![Coverage Status](https://img.shields.io/coveralls/microlinkhq/is-antibot.svg?style=flat-square)](https://coveralls.io/github/microlinkhq/is-antibot)
[![NPM Status](https://img.shields.io/npm/dm/is-antibot.svg?style=flat-square)](https://www.npmjs.org/package/is-antibot)

> Lightweight, vendor-agnostic library to identify antibot responses.

It helps you to identify if a response from a popular site (like **LinkedIn**, **Instagram**, or **YouTube**) is actually an antibot challenge, such as a **403 Forbidden**, **429 Too Many Requests**, or a **"Please prove you're human"** challenge.

## Why

Websites receiving massive quantities of traffic throughout the day have sophisticated antibot systems to prevent automated access.

These systems are often powered by providers like **Cloudflare**, **DataDome**, **Akamai**, or **Vercel**. When you try to fetch the HTML of these sites without the right tools, you often end up with a blocked response that contains no useful data, just the challenge itself.

**is-antibot** is a lightweight, vendor-agnostic JavaScript library that identifies when a response is actually an antibot challenge.

## Install

```bash
$ npm install is-antibot --save
```

## Usage

The library expects a [Response](https://developer.mozilla.org/en-US/docs/Web/API/Response) object or an object representing HTTP response headers as input.

It's designed to be used after a fetch request to determine if the response was blocked or challenged by an antibot system:

```js
const isAntibot = require('is-antibot')

const response = await fetch('https://example.com')
const { detected, provider } = isAntibot(response)

if (detected) {
  console.log(`Antibot detected: ${provider}`)
}
```

## License

**is-antibot** © [microlink.io](https://microlink.io), released under the [MIT](https://github.com/microlinkhq/is-antibot/blob/master/LICENSE.md) License.<br>
Authored and maintained by [microlink.io](https://microlink.io) with help from [contributors](https://github.com/microlinkhq/is-antibot/contributors).

> [microlink.io](https://microlink.io) · GitHub [microlink.io](https://github.com/microlinkhq) · X [@microlinkhq](https://x.com/microlinkhq)
