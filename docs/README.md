<div align="center">
  <img src="https://cdn.microlink.io/logo/banner.png" alt="Microlink" width="2400" height="500">
  <br>
  <br>
  <p>Know exactly who blocked your request and why. Detect antibot and CAPTCHA challenges from 30+ providers using five response signals in a lightweight package, then route retries, proxy swaps, or headless fallback only when needed.</p>
</div>

## Quick start

Install the package:

```bash
npm install is-antibot
```

Pass any HTTP response and get back a detection result:

```js
const isAntibot = require('is-antibot')

const response = await fetch('https://example.com')
const html = await response.text()

const { detected, provider, detection } = isAntibot({
  headers: response.headers,
  statusCode: response.status,
  html,
  url: response.url
})

if (detected) {
  console.log(`Blocked by ${provider} (via ${detection})`)
  // => "Blocked by cloudflare (via headers)"
}
```

Works with [got](https://github.com/sindresorhus/got), [axios](https://github.com/axios/axios), [undici](https://github.com/nodejs/undici), or any HTTP library:

## How detection works

is-antibot inspects five signals from any HTTP response to identify the provider that blocked the request:

- **Headers** — Provider-specific response headers like `cf-mitigated`, `x-dd-b`, `x-vercel-mitigated`, or dynamic Shape Security patterns.
- **Cookies** — Tracking cookies such as `cf_clearance`, `_abck`, `datadome`, `_px3`, or `aws-waf-token` in `set-cookie` headers.
- **HTML** — Fingerprints in the response body: challenge scripts, SDK references, or provider-specific DOM patterns.
- **URL** — CAPTCHA provider domains and challenge endpoints in the response URL.
- **Status Code** — Platform-specific status codes like LinkedIn's `999` or Reddit's `403` challenge pages.

Each provider has unique fingerprints across one or more of these signals. The library checks them in priority order and returns the first match.

## Providers

Supported providers by detection signal:

| Provider                     | Headers | Cookies | HTML  |  URL  | Status Code |
| ---------------------------- | :-----: | :-----: | :---: | :---: | :---------: |
| **Akamai**                   |    ✓    |    ✓    |   ✓   |       |             |
| **AliExpress CAPTCHA**       |         |         |   ✓   |   ✓   |             |
| **Anubis**                   |         |         |   ✓   |       |             |
| **AWS WAF**                  |    ✓    |    ✓    |   ✓   |       |             |
| **Captcha.eu**               |         |         |   ✓   |   ✓   |             |
| **Cheq**                     |         |         |   ✓   |   ✓   |             |
| **Cloudflare**               |    ✓    |    ✓    |       |       |             |
| **Cloudflare Turnstile**     |         |         |   ✓   |   ✓   |             |
| **DataDome**                 |    ✓    |    ✓    |       |       |             |
| **Friendly Captcha**         |         |         |   ✓   |   ✓   |             |
| **FunCaptcha** (Arkose Labs) |         |         |   ✓   |   ✓   |             |
| **GeeTest**                  |         |         |   ✓   |   ✓   |             |
| **hCaptcha**                 |         |         |   ✓   |   ✓   |             |
| **Imperva / Incapsula**      |    ✓    |    ✓    |   ✓   |       |             |
| **Instagram**                |         |         |   ✓   |       |             |
| **Kasada**                   |    ✓    |         |   ✓   |       |             |
| **LinkedIn**                 |         |         |       |       |      ✓      |
| **Meetrics**                 |         |         |   ✓   |   ✓   |             |
| **Ocule**                    |         |         |   ✓   |   ✓   |             |
| **PerimeterX**               |    ✓    |    ✓    |   ✓   |       |             |
| **QCloud Captcha** (Tencent) |         |         |   ✓   |   ✓   |             |
| **reCAPTCHA**                |         |         |   ✓   |   ✓   |             |
| **Reblaze**                  |         |    ✓    |   ✓   |       |             |
| **Reddit**                   |         |         |   ✓   |       |      ✓      |
| **Shape Security**           |    ✓    |         |   ✓   |       |             |
| **Sucuri**                   |         |         |   ✓   |       |             |
| **ThreatMetrix**             |         |         |   ✓   |   ✓   |             |
| **Vercel**                   |    ✓    |         |       |       |             |
| **YouTube**                  |         |         |   ✓   |       |             |

<p class="provider-request">Miss something?<br><a class="button button-primary" href="https://github.com/microlinkhq/is-antibot/issues/new?title=Request%20a%20provider" target="_blank" rel="noopener noreferrer">Request a provider</a></p>

## FAQ

### What HTTP clients does it support?

Any client that gives you access to headers and response body. It works with `fetch`, `got`, `axios`, `undici`, `node-fetch`, or raw `http` responses. Pass `headers`, `html` (or `body`), `url`, and `statusCode` (or `status`).

### Does it detect the challenge or the provider presence?

It detects active challenges and blocking signals, not passive provider presence. For example, a Cloudflare-protected site that serves content normally won't trigger detection — only when `cf-mitigated: challenge` is present.

### Can I add custom providers?

Not directly in the library, but the source is straightforward to extend. Each provider is a simple pattern check against headers, cookies, HTML, URL, or status code.

### How is it different from browser-based detection?

Browser-based tools like [Antibot-Detector](https://github.com/scrapfly/Antibot-Detector) run in the browser and inspect the live DOM. is-antibot works server-side with raw HTTP responses — no browser needed, much faster, and works in any Node.js pipeline.
