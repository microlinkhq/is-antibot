/* global Node */

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

const decorateWhySection = section => {
  const heading = section.querySelector('h2#why')
  if (!heading) return
  if (heading.parentElement?.classList.contains('why-story')) return

  const wrapper = document.createElement('section')
  wrapper.className = 'why-story'
  wrapper.setAttribute('aria-label', 'Why')

  heading.parentNode.insertBefore(wrapper, heading)

  let node = heading
  while (node) {
    const next = node.nextSibling
    wrapper.append(node)

    if (next && next.nodeType === Node.ELEMENT_NODE && next.tagName === 'H2') {
      break
    }

    node = next
  }
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
  decorateWhySection(section)
  decorateCodeBlocks(section)
  decorateTables(section)
  disableDocsifyDefaultScrollSpy(section)
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
