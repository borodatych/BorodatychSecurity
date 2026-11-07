/** Ресурсы страницы, из которых собирается стартовый CSP */
export interface PageResources {
  script: string[]
  style: string[]
  img: string[]
  font: string[]
  connect: string[]
  frame: string[]
  form: string[]
  inlineScript: boolean
  inlineStyle: boolean
}

function attribute(tag: string, name: string): string | null {
  // Пробел перед именем не даёт принять data-src за src
  const pattern = new RegExp(
    `(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`,
    'i',
  )
  const match = pattern.exec(tag)
  if (match === null) return null
  return match[1] ?? match[2] ?? match[3] ?? ''
}

function originOf(reference: string, pageUrl: string): string | null {
  try {
    const url = new URL(reference, pageUrl)
    if (url.protocol === 'data:') return 'data:'
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
    const base = new URL(pageUrl)
    return url.origin === base.origin ? 'self' : url.origin
  } catch {
    return null
  }
}

function pushOrigin(list: string[], reference: string, pageUrl: string, allowData: boolean): void {
  const origin = originOf(reference, pageUrl)
  if (origin === null) return
  if (origin === 'data:' && !allowData) return
  if (!list.includes(origin)) list.push(origin)
}

function srcsetUrls(value: string): string[] {
  return value
    .split(',')
    .map((part) => part.trim().split(/\s+/)[0] ?? '')
    .filter((url) => url.length > 0)
}

/** Собирает ресурсы страницы без зависимостей: только origin, свой origin — self */
export function collectResources(html: string, pageUrl: string): PageResources {
  const res: PageResources = {
    script: [],
    style: [],
    img: [],
    font: [],
    connect: [],
    frame: [],
    form: [],
    inlineScript: false,
    inlineStyle: false,
  }

  const scripts = html.match(/<script\b[^>]*>/gi) ?? []
  for (const tag of scripts) {
    const src = attribute(tag, 'src')
    if (src === null) {
      res.inlineScript = true
    } else {
      pushOrigin(res.script, src, pageUrl, false)
    }
  }

  const links = html.match(/<link\b[^>]*>/gi) ?? []
  for (const tag of links) {
    const rel = (attribute(tag, 'rel') ?? '').toLowerCase()
    const href = attribute(tag, 'href')
    if (href === null) continue
    const rels = rel.split(/\s+/)
    if (rels.includes('stylesheet') || rels.includes('style')) {
      pushOrigin(res.style, href, pageUrl, false)
    }
    if (rels.includes('preload') && (attribute(tag, 'as') ?? '').toLowerCase() === 'font') {
      pushOrigin(res.font, href, pageUrl, false)
    }
  }

  const images = html.match(/<img\b[^>]*>/gi) ?? []
  for (const tag of images) {
    const src = attribute(tag, 'src')
    if (src !== null) pushOrigin(res.img, src, pageUrl, true)
    const srcset = attribute(tag, 'srcset')
    if (srcset !== null) {
      for (const url of srcsetUrls(srcset)) pushOrigin(res.img, url, pageUrl, true)
    }
  }

  const frames = html.match(/<iframe\b[^>]*>/gi) ?? []
  for (const tag of frames) {
    const src = attribute(tag, 'src')
    if (src !== null) pushOrigin(res.frame, src, pageUrl, false)
  }

  const forms = html.match(/<form\b[^>]*>/gi) ?? []
  for (const tag of forms) {
    const action = attribute(tag, 'action')
    if (action !== null) pushOrigin(res.form, action, pageUrl, false)
  }

  if (/<style\b/i.test(html) || /(?:^|\s)style\s*=\s*["'][^"']+["']/i.test(html)) {
    res.inlineStyle = true
  }

  res.script.sort()
  res.style.sort()
  res.img.sort()
  res.font.sort()
  res.connect.sort()
  res.frame.sort()
  res.form.sort()
  return res
}

function withSelf(sources: readonly string[]): string[] {
  const result = ["'self'"]
  for (const source of sources) {
    if (source !== 'self' && !result.includes(source)) result.push(source)
  }
  return result
}

/** Собирает политику CSP по найденным ресурсам; inline-скриптам нужен nonce, не unsafe-inline */
export function buildCsp(res: PageResources): string {
  const style = withSelf(res.style)
  if (res.inlineStyle && !style.includes("'unsafe-inline'")) style.push("'unsafe-inline'")

  const directives = [
    "default-src 'self'",
    `script-src ${withSelf(res.script).join(' ')}`,
    `style-src ${style.join(' ')}`,
    `img-src ${withSelf(res.img).join(' ')}`,
    `font-src ${withSelf(res.font).join(' ')}`,
    `connect-src ${withSelf(res.connect).join(' ')}`,
    `frame-src ${withSelf(res.frame).join(' ')}`,
    `form-action ${withSelf(res.form).join(' ')}`,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'self'",
  ]
  return directives.join('; ')
}
