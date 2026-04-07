const createSiteHeader = () => {
  let header = document.querySelector('.site-header')

  if (!header) {
    header = document.createElement('header')
    header.className = 'site-header'
    header.innerHTML = `
      <a class="site-brand" href="/" aria-label="is-antibot home">
        <img src="https://cdn.microlink.io/logo/favicon.svg" alt="" width="18" height="18">
      </a>
      <nav class="site-nav" aria-label="Primary">
      <a href="#/?id=why" data-section="why">Why</a>
        <a href="#/?id=quick-start" data-section="quick-start">Quick start</a>
        <a href="#/?id=how-it-works" data-section="how-it-works">How it works</a>
        <a href="#/?id=providers" data-section="providers">Providers</a>
      </nav>
      <a class="site-cta" href="https://github.com/microlinkhq/is-antibot" target="_blank" rel="noopener noreferrer">GitHub</a>
    `

    document.body.insertBefore(header, document.querySelector('#app'))
  }

  setupSiteHeaderReveal(header)

  return header
}

const PRETEXT_SOURCE =
  'https://cdn.jsdelivr.net/npm/@chenglou/pretext@0.0.4/+esm'

let pretextModulePromise

const loadPretext = async () => {
  if (!pretextModulePromise) {
    pretextModulePromise = import(PRETEXT_SOURCE)
      .then(module => {
        if (
          typeof module.prepareWithSegments !== 'function' ||
          typeof module.walkLineRanges !== 'function'
        ) {
          return null
        }

        return module
      })
      .catch(() => null)
  }

  return pretextModulePromise
}

const pxValue = value => {
  const parsed = Number.parseFloat(value)
  return Number.isFinite(parsed) ? parsed : 0
}

const getStoryFont = styles => {
  if (styles.font) return styles.font

  return `${styles.fontStyle} ${styles.fontVariant} ${styles.fontWeight} ${styles.fontSize} ${styles.fontFamily}`
}

const setupSiteHeaderReveal = header => {
  if (header.dataset.revealBound === 'true') return

  header.dataset.revealBound = 'true'
  const revealOffset = 128

  const update = () => {
    const isVisible = window.scrollY > revealOffset

    header.classList.toggle('is-visible', isVisible)
    header.toggleAttribute('aria-hidden', !isVisible)
    header.inert = !isVisible
  }

  window.addEventListener('scroll', update, { passive: true })
  window.addEventListener('resize', update)
  update()
}

const createStorySection = () => {
  const story = document.createElement('section')
  story.className = 'story-section reveal-on-load'
  story.setAttribute('aria-label', 'Why we built is-antibot')
  story.innerHTML = `
    <p>Your request returned <span class="status-flicker" aria-hidden="true"><span>429 TOO_MANY_REQUESTS</span><span>401 UNAUTHORIZED</span><span>403 FORBIDDEN</span></span></p>
    <p>You got a challenge page. A CAPTCHA. A JavaScript puzzle.</p>
    <p>You were <strong class="is-error">blocked</strong>, and you didn't know, wasting infrastructure resources and time.</p>
    <p>With <strong>is-antibot</strong>, you can <br>see who and how blocked you, maximizing efficiency and minimizing disruptions.</p>
  `
  story.querySelector('p:nth-child(3)')?.after(createHeroGraph())
  return story
}

const createHeroGraph = () => {
  const graph = document.createElement('figure')
  graph.className = 'hero-graph reveal-on-load'
  graph.setAttribute('aria-label', 'Illustrative antibot provider distribution')
  graph.innerHTML = `
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
        <text class="hero-graph__label" x="154" y="42">cloudflare</text>
        <path class="hero-graph__leader hero-graph__leader--turnstile" d="M175 113 L150 98 L52 98"></path>
        <text class="hero-graph__label" x="52" y="90">cloudflare-turnstile</text>
        <path class="hero-graph__leader hero-graph__leader--aws" d="M164 162 L112 160 L92 160"></path>
        <text class="hero-graph__label" x="92" y="152">aws-waf</text>
        <path class="hero-graph__leader hero-graph__leader--akamai" d="M176 220 L142 230 L108 230"></path>
        <text class="hero-graph__label" x="108" y="252">akamai</text>
        <path class="hero-graph__leader hero-graph__leader--youtube" d="M211 265 L192 286 L140 286"></path>
        <text class="hero-graph__label" x="140" y="310">youtube</text>
      </g>
    </svg>
  `
  return graph
}

const decorateHero = section => {
  const hero = section.querySelector('div[align="center"]')

  if (!hero || hero.dataset.enhanced === 'true') return

  hero.dataset.enhanced = 'true'
  hero.className = 'hero-block'

  const intro = hero.querySelector('p')
  const logo = hero.querySelector('img')
  const copy = document.createElement('div')
  const kicker = document.createElement('a')
  const kickerText = document.createElement('span')
  const title = document.createElement('h1')
  const actions = document.createElement('div')

  copy.className = 'hero-copy'
  kicker.className = 'hero-kicker reveal-on-load'
  kicker.href = '#/?id=quick-start'
  kickerText.className = 'hero-kicker-text'
  kickerText.textContent = 'npm i is-antibot'
  title.className = 'hero-title reveal-on-load'
  title.innerHTML = 'Know exactly who blocked your request and why.'
  actions.className = 'hero-actions reveal-on-load'
  actions.innerHTML = `
    <a class="button button-primary" href="#/?id=quick-start">Start using it</a>
    <a class="button button-secondary" href="https://github.com/microlinkhq/is-antibot" target="_blank" rel="noopener noreferrer">View on GitHub</a>
  `

  logo?.remove()
  kicker.append(kickerText)
  copy.append(kicker, title)

  if (intro) {
    intro.classList.add('hero-lede', 'reveal-on-load')
    copy.append(intro)
  }

  copy.append(actions)
  hero.replaceChildren(copy)

  if (!section.querySelector('.story-section')) hero.after(createStorySection())
}

const decorateCodeBlocks = section => {
  section.querySelectorAll('pre').forEach(pre => {
    if (pre.parentElement?.classList.contains('code-shell')) return

    const shell = document.createElement('div')
    const header = document.createElement('div')

    shell.className = 'code-shell'
    header.className = 'code-shell__header'
    header.innerHTML = `
      <span class="code-shell__dots" aria-hidden="true"><i></i><i></i><i></i></span>
    `

    pre.parentNode.insertBefore(shell, pre)
    shell.append(header, pre)
  })
}

const decorateTables = section => {
  section.querySelectorAll('table').forEach(table => {
    if (table.parentElement?.classList.contains('table-shell')) return

    const shell = document.createElement('div')
    shell.className = 'table-shell'

    let previous = table.previousElementSibling
    while (previous && !previous.matches('h2')) {
      previous = previous.previousElementSibling
    }

    if (previous?.id === 'providers') {
      shell.classList.add('table-shell--wide')
    }

    table.parentNode.insertBefore(shell, table)
    shell.append(table)
  })
}

const disableDocsifyDefaultScrollSpy = section => {
  section
    .querySelectorAll(':is(h1, h2, h3, h4, h5) > a.anchor[data-id]')
    .forEach(anchor => anchor.classList.remove('anchor'))
}

let teardownNavigationTracking = () => {}
let teardownStoryCentering = () => {}

const setupStoryCentering = section => {
  const story = section.querySelector('.story-section')
  if (!story) return () => {}

  const paragraphs = [...story.querySelectorAll('p')]
  if (!paragraphs.length) return () => {}

  const preparedCache = new Map()
  let frame = null
  let cancelled = false

  const centerParagraphs = async () => {
    frame = null

    const pretext = await loadPretext()
    if (cancelled || !pretext) return

    const { prepareWithSegments, walkLineRanges } = pretext
    const measures = []

    for (const paragraph of paragraphs) {
      paragraph.style.width = ''

      const text = paragraph.textContent?.trim()
      if (!text) continue

      const styles = window.getComputedStyle(paragraph)
      const font = getStoryFont(styles)
      const maxWidth =
        pxValue(styles.maxWidth) ||
        paragraph.clientWidth ||
        paragraph.getBoundingClientRect().width

      if (!font || maxWidth <= 0) continue

      const cacheKey = `${font}:${text}`
      let prepared = preparedCache.get(cacheKey)

      if (!prepared) {
        prepared = prepareWithSegments(text, font)
        preparedCache.set(cacheKey, prepared)
      }

      let widestLine = 0
      walkLineRanges(prepared, maxWidth, line => {
        if (line.width > widestLine) widestLine = line.width
      })

      if (widestLine > 0) measures.push({ paragraph, maxWidth, widestLine })
    }

    if (!measures.length) return

    const sharedMaxWidth = Math.min(...measures.map(item => item.maxWidth))
    const sharedWidestLine = Math.max(...measures.map(item => item.widestLine))
    const sharedWidth = Math.ceil(Math.min(sharedMaxWidth, sharedWidestLine))

    for (const item of measures) {
      item.paragraph.style.width = `${sharedWidth}px`
    }
  }

  const requestCentering = () => {
    if (frame !== null) window.cancelAnimationFrame(frame)
    frame = window.requestAnimationFrame(() => {
      centerParagraphs().catch(() => null)
    })
  }

  window.addEventListener('resize', requestCentering)

  if (document.fonts?.ready) {
    document.fonts.ready.then(() => {
      if (!cancelled) requestCentering()
    })
  }

  requestCentering()

  return () => {
    cancelled = true
    window.removeEventListener('resize', requestCentering)
    if (frame !== null) window.cancelAnimationFrame(frame)
  }
}

const setupNavigationTracking = section => {
  const nav = document.querySelector('.site-nav')
  if (!nav) return () => {}

  const links = [...nav.querySelectorAll('a[data-section]')]
  const headings = [...section.querySelectorAll('h2[id], h3[id]')]
  const linkById = new Map(links.map(link => [link.dataset.section, link]))
  const trackedHeadings = headings.filter(heading => linkById.has(heading.id))
  let frame = null

  const activate = id => {
    links.forEach(link => {
      link.classList.toggle('is-active', link.dataset.section === id)
      if (link.dataset.section === id) {
        link.setAttribute('aria-current', 'location')
      } else link.removeAttribute('aria-current')
    })
  }

  const refresh = () => {
    frame = null

    const offset = Math.max(160, window.innerHeight * 0.32)
    let active = trackedHeadings[0]?.id || links[0]?.dataset.section

    for (const heading of trackedHeadings) {
      if (heading.offsetTop <= window.scrollY + offset) active = heading.id
      else break
    }

    if (active) activate(active)
  }

  const requestRefresh = () => {
    if (frame === null) frame = window.requestAnimationFrame(refresh)
  }

  window.addEventListener('scroll', requestRefresh, { passive: true })
  window.addEventListener('resize', requestRefresh)
  requestRefresh()
  window.setTimeout(requestRefresh, 140)

  return () => {
    window.removeEventListener('scroll', requestRefresh)
    window.removeEventListener('resize', requestRefresh)
    if (frame !== null) window.cancelAnimationFrame(frame)
  }
}

const enhancePage = () => {
  teardownStoryCentering()
  teardownStoryCentering = () => {}
  teardownNavigationTracking()
  teardownNavigationTracking = () => {}

  const section = document.querySelector('.markdown-section')
  const content = document.querySelector('.content')
  const sidebar = document.querySelector('.sidebar')

  createSiteHeader()

  if (!section) return

  if (content) {
    content.id = 'main-content'
    content.setAttribute('role', 'main')
    content.setAttribute('tabindex', '-1')
  }

  if (sidebar) {
    sidebar.setAttribute('role', 'navigation')
    sidebar.setAttribute('aria-label', 'Docsify navigation')
  }

  decorateHero(section)
  decorateCodeBlocks(section)
  decorateTables(section)
  disableDocsifyDefaultScrollSpy(section)
  teardownStoryCentering = setupStoryCentering(section)
  teardownNavigationTracking = setupNavigationTracking(section)
}

window.$docsify = {
  name: 'is-antibot',
  repo: 'microlinkhq/is-antibot',
  logo: 'https://cdn.microlink.io/logo/trim.png',
  externalLinkRel: 'noopener noreferrer',
  subMaxLevel: 2,
  auto2top: true,
  maxLevel: 3,
  plugins: [
    hook => {
      hook.doneEach(() => {
        enhancePage()

        const brand = document.querySelector('.site-brand')
        if (!brand || brand.dataset.bound) return

        brand.dataset.bound = 'true'
        brand.onclick = event => {
          event.preventDefault()
          const reducedMotion = window.matchMedia(
            '(prefers-reduced-motion: reduce)'
          ).matches
          window.scrollTo({
            top: 0,
            behavior: reducedMotion ? 'auto' : 'smooth'
          })
        }
      })
    }
  ]
}
