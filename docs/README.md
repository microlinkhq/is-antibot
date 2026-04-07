<div align="center">
  <img src="https://antibot.microlink.io/static/banner.png" alt="is-antibot" width="2400" height="500">
  <br>
  <br>
  <p><strong>is-antibot</strong> detects antibot and CAPTCHA challenges from 30+ providers using signals.</p>
</div>


## Why?

[microlink.io](https://microlink.io) handles +700M requests every month.

When you're building infrastructure that needs an URL as input for getting data, you’re constantly interacting with defenses designed to stop you.

Modern antibot systems operate at multiple layers—often before your request even reaches application code.

Common signals include:

- **IP reputation**: Data-center IPs are flagged by default. Residential traffic behaves differently.
- **HTTP consistency**: Headers must match a real browser profile—not just User-Agent, but the full set.
- **TLS fingerprints (JA3)**: The way a client negotiates TLS leaks whether it’s a browser or a script.
- **Behavioral heuristics**: Timing, navigation order, and interaction patterns matter.
- **JavaScript fingerprinting**: Canvas, WebGL, fonts, screen size—small inconsistencies are enough.

Based on these signals, a request is either:

- **Allowed**: If the heuristics indicate a legitimate human visitor, the request is passed through to the target website.
- **Blocked**: If the request is highly suspicious (e.g., coming from a known malicious IP or with a broken TLS fingerprint), it is blocked immediately with a 403 Forbidden or 429 Too Many Requests error.
- **Challenged**: If the system is unsure, it serves a "challenge"—such as a CAPTCHA or a JavaScript-based interstitial—that must be resolved before the actual content is released.

Our library **is-antibot** does something fundamental: it tells you that a non success resolution happened  and who triggered it, so you will have all the information to take a better decisiong of what to do next.

## Quick start

Install it as dependency is the first thing to do:

```bash
npm install is-antibot
```

**is-antibot** is designed to have a minimal footprint. It works with static HTTP response analysis.

No headless browser is required. Just pass it the response information:

```js
import isAntibot from 'is-antibot'

const response = await fetch('https://example.com')

const { detected, provider, detection } = isAntibot({
  headers: response.headers,
  statusCode: response.status,
  html: await response.text(),
  url: response.url
})

if (detected) {
  console.log(`Blocked by ${provider} (via ${detection})`)
  // => "Blocked by CloudFlare (via headers)"
}
```

The result is deterministic and fast—designed to run on every request without becoming the bottleneck.

It works with any HTTP client, including [got](https://github.com/sindresorhus/got), [axios](https://github.com/axios/axios), [undici](https://github.com/nodejs/undici) or just the vanilla [fetch](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API).

## How it works

At a high level, **is-antibot** classifies challenge responses using:

- **HTTP status patterns**: Certain platforms use unusual status codes when blocking automation; for example, LinkedIn can return `999` and Reddit can return `403` on challenge flows.
- **Known challenge signatures**: Challenge pages often include recognizable artifacts like CAPTCHA widgets, interstitial templates, or verification scripts.
- **Response headers and body markers**: Blocking responses usually expose hints in headers and HTML, such as mitigation headers, challenge tokens, or provider-specific script references.
- **Provider-specific fingerprints**: Each provider leaves a distinct combination of signals; for example, Cloudflare commonly surfaces `cf-mitigated: challenge`, while other providers rely more on cookie, URL, or HTML fingerprints.

Each provider has unique fingerprints across one or more of these signals. The library checks them in priority order and returns the first match.

## Providers

**is-antibot** currently detects challenges across antibot systems, CAPTCHA vendors, and platform-specific protection flows.

<div class="provider-guides-table-wrap">
  <table class="provider-guides-table">
    <thead>
      <tr>
        <th>Provider</th>
        <th>Category</th>
        <th>Signals</th>
        <th>Detection methods</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>Akamai</td><td>Antibot</td><td>3</td><td><span class="provider-chip">Headers</span><span class="provider-chip">Cookies</span><span class="provider-chip">HTML</span></td></tr>
      <tr><td>AliExpress CAPTCHA</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>Anubis</td><td>Antibot</td><td>1</td><td><span class="provider-chip">HTML</span></td></tr>
      <tr><td>AWS WAF</td><td>Antibot</td><td>3</td><td><span class="provider-chip">Headers</span><span class="provider-chip">Cookies</span><span class="provider-chip">HTML</span></td></tr>
      <tr><td>Captcha.eu</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>Cheq</td><td>Antibot</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>Cloudflare</td><td>Antibot</td><td>2</td><td><span class="provider-chip">Headers</span><span class="provider-chip">Cookies</span></td></tr>
      <tr><td>Cloudflare Turnstile</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>DataDome</td><td>Antibot</td><td>2</td><td><span class="provider-chip">Headers</span><span class="provider-chip">Cookies</span></td></tr>
      <tr><td>Friendly Captcha</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>FunCaptcha (Arkose Labs)</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>GeeTest</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>hCaptcha</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>Imperva / Incapsula</td><td>Antibot</td><td>3</td><td><span class="provider-chip">Headers</span><span class="provider-chip">Cookies</span><span class="provider-chip">HTML</span></td></tr>
      <tr><td>Instagram</td><td>Platform-specific</td><td>1</td><td><span class="provider-chip">HTML</span></td></tr>
      <tr><td>Kasada</td><td>Antibot</td><td>2</td><td><span class="provider-chip">Headers</span><span class="provider-chip">HTML</span></td></tr>
      <tr><td>LinkedIn</td><td>Platform-specific</td><td>1</td><td><span class="provider-chip">Status Code</span></td></tr>
      <tr><td>Meetrics</td><td>Antibot</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>Ocule</td><td>Antibot</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>PerimeterX</td><td>Antibot</td><td>3</td><td><span class="provider-chip">Headers</span><span class="provider-chip">Cookies</span><span class="provider-chip">HTML</span></td></tr>
      <tr><td>QCloud Captcha</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>reCAPTCHA</td><td>CAPTCHA</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>Reblaze</td><td>Antibot</td><td>2</td><td><span class="provider-chip">Cookies</span><span class="provider-chip">HTML</span></td></tr>
      <tr><td>Reddit</td><td>Platform-specific</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">Status Code</span></td></tr>
      <tr><td>Shape Security</td><td>Antibot</td><td>2</td><td><span class="provider-chip">Headers</span><span class="provider-chip">HTML</span></td></tr>
      <tr><td>Sucuri</td><td>Antibot</td><td>1</td><td><span class="provider-chip">HTML</span></td></tr>
      <tr><td>ThreatMetrix</td><td>Antibot</td><td>2</td><td><span class="provider-chip">HTML</span><span class="provider-chip">URL</span></td></tr>
      <tr><td>Vercel</td><td>Antibot</td><td>1</td><td><span class="provider-chip">Headers</span></td></tr>
      <tr><td>YouTube</td><td>Platform-specific</td><td>1</td><td><span class="provider-chip">HTML</span></td></tr>
    </tbody>
  </table>
</div>

Use this table as a quick coverage map when building retry logic, escalation rules, or provider-specific analytics in your scraping pipeline.

In case you are missing a provider or signal detection, please [report to us](https://github.com/microlinkhq/is-antibot/issues/new?title=Request%20a%20provider), and we will continue evolving the library.
