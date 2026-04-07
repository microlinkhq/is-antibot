<div align="center">
  <img src="https://antibot.microlink.io/static/banner.png" alt="is-antibot" width="2400" height="500" fetchpriority="high">
  <br>
  <br>
  <p><strong>is-antibot</strong> detects antibot and CAPTCHA challenges from 30+ providers using signals.</p>
</div>


## Why?

[microlink.io](https://microlink.io) handles +700M requests every month.

When you're building infrastructure that needs an URL as input for getting data, you’re constantly interacting with defenses designed to stop you.

<div class="why-scene" aria-label="Why challenge detection matters">
  <p><span style="margin-right: 8px">A request can experience</span><span class="status-flicker" role="text" aria-label="429 Too Many Requests, 401 Unauthorized, or 403 Forbidden"><span aria-hidden="true">429 TOO_MANY_REQUESTS</span><span aria-hidden="true">401 UNAUTHORIZED</span><span aria-hidden="true">403 FORBIDDEN</span></span></p>
  <p>Followed by a challenge page. A captcha. A JavaScript puzzle.</p>
</div>

Modern antibot systems operate at multiple layers, often before your request even reaches the application code.

Our library **is-antibot** does something fundamental: it tells you when a non-success resolution happens and who triggered it, so you can make a better decision about what to do next.

<figure class="hero-graph" aria-label="Illustrative antibot provider distribution">
  <svg class="hero-graph__svg" viewBox="0 0 520 340" role="img" aria-labelledby="hero-graph-title">
    <title id="hero-graph-title">Illustrative antibot providers by detected blocks (example data)</title>
    <g class="hero-graph__donut" transform="rotate(-90 260 170)">
      <circle class="hero-graph__slice hero-graph__slice--recaptcha" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="44.7 55.3" stroke-dashoffset="0"></circle>
      <circle class="hero-graph__slice hero-graph__slice--cloudflare" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="12.6 87.4" stroke-dashoffset="-44.7"></circle>
      <circle class="hero-graph__slice hero-graph__slice--turnstile" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="8.5 91.5" stroke-dashoffset="-57.3"></circle>
      <circle class="hero-graph__slice hero-graph__slice--aws" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="6.8 93.2" stroke-dashoffset="-65.8"></circle>
      <circle class="hero-graph__slice hero-graph__slice--akamai" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="5.6 94.4" stroke-dashoffset="-72.6"></circle>
      <circle class="hero-graph__slice hero-graph__slice--youtube" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="3.8 96.2" stroke-dashoffset="-78.2"></circle>
      <circle class="hero-graph__slice hero-graph__slice--secondary-a" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="3.4 96.6" stroke-dashoffset="-82"></circle>
      <circle class="hero-graph__slice hero-graph__slice--secondary-b" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="3.1 96.9" stroke-dashoffset="-85.4"></circle>
      <circle class="hero-graph__slice hero-graph__slice--secondary-c" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="2.8 97.2" stroke-dashoffset="-88.5"></circle>
      <circle class="hero-graph__slice hero-graph__slice--secondary-d" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="2.4 97.6" stroke-dashoffset="-91.3"></circle>
      <circle class="hero-graph__slice hero-graph__slice--secondary-e" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="2.1 97.9" stroke-dashoffset="-93.7"></circle>
      <circle class="hero-graph__slice hero-graph__slice--secondary-f" cx="260" cy="170" r="96" pathLength="100" stroke-dasharray="4.2 95.8" stroke-dashoffset="-95.8"></circle>
    </g>
    <circle class="hero-graph__hole" cx="260" cy="170" r="54"></circle>
    <text class="hero-graph__center" x="260" y="165">blocked</text>
    <text class="hero-graph__center hero-graph__center--sub" x="260" y="190">providers</text>
    <g class="hero-graph__labels">
      <path class="hero-graph__leader hero-graph__leader--recaptcha" d="M366 176 L390 172 L450 172"></path>
      <text class="hero-graph__label" x="456" y="178">recaptcha</text>
      <path class="hero-graph__leader hero-graph__leader--cloudflare" d="M218 76 L208 52 L154 52"></path>
      <text class="hero-graph__label" x="154" y="42">akamai</text>
      <path class="hero-graph__leader hero-graph__leader--turnstile" d="M175 113 L150 98 L52 98"></path>
      <text class="hero-graph__label" x="52" y="90">cloudflare-turnstile</text>
      <path class="hero-graph__leader hero-graph__leader--aws" d="M164 162 L112 160 L92 160"></path>
      <text class="hero-graph__label" x="92" y="152">aws-waf</text>
      <path class="hero-graph__leader hero-graph__leader--akamai" d="M176 220 L142 230 L108 230"></path>
      <text class="hero-graph__label" x="108" y="252">akamai</text>
      <path class="hero-graph__leader hero-graph__leader--youtube" d="M211 265 L192 286 L140 286"></path>
      <text class="hero-graph__label" x="140" y="310">hcaptcha</text>
    </g>
  </svg>
</figure>

Common signals include:

- **IP reputation**: Data-center IPs are flagged by default. Residential traffic behaves differently.
- **HTTP consistency**: Headers must match a real browser profile—not just User-Agent, but the full set.
- **TLS fingerprints (JA3)**: The way a client negotiates TLS leaks whether it’s a browser or a script.
- **Behavioral heuristics**: Timing, navigation order, and interaction patterns matter.
- **JavaScript fingerprinting**: Canvas, WebGL, fonts, screen size—small inconsistencies are enough.

Based on these signals, a request is either:

- **Allowed**: If the heuristics indicate a legitimate human visitor, the request is passed through to the target website.
- **Blocked**: If the request is highly suspicious (e.g., coming from a known malicious IP or with a broken TLS fingerprint), it is blocked immediately with a 403 Forbidden or 429 Too Many Requests error.
- **Challenged**: If the system is unsure, it serves a “challenge”—such as a CAPTCHA or a JavaScript-based interstitial—that must be resolved before the actual content is released.

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
