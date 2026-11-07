import { ru } from '../i18n/ru'
import { matchesDomain } from './nginx'
import type { FixEdit, FixSkip } from './types'

export const CADDYFILE_PATH = '/etc/caddy/Caddyfile'
export const CADDY_MARKER = '# borodatych-security'
export const CADDY_SNIPPET = 'borodatych-security'

export interface CaddyBlock {
  kind: 'site' | 'snippet' | 'global'
  address: string
  name: string | null
  start: number
  open: number
  close: number
  line: number
  /** Перед сниппетом стоит наш маркер */
  marked: boolean
}

function findMatchingBrace(text: string, open: number): number {
  let depth = 0
  let quote: string | null = null
  let i = open
  while (i < text.length) {
    const char = text[i] ?? ''
    if (quote !== null) {
      if (char === '\\') {
        i += 2
        continue
      }
      if (char === quote) quote = null
      i += 1
      continue
    }
    if (char === '#') {
      const next = text.indexOf('\n', i)
      i = next === -1 ? text.length : next + 1
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      i += 1
      continue
    }
    if (char === '{') depth += 1
    if (char === '}') {
      depth -= 1
      if (depth === 0) return i
    }
    i += 1
  }
  return -1
}

function stripComments(value: string): string {
  let result = ''
  let quote: string | null = null
  let i = 0
  while (i < value.length) {
    const char = value[i] ?? ''
    if (quote !== null) {
      result += char
      if (char === '\\') {
        result += value[i + 1] ?? ''
        i += 2
        continue
      }
      if (char === quote) quote = null
      i += 1
      continue
    }
    if (char === '#') {
      const next = value.indexOf('\n', i)
      if (next === -1) break
      result += '\n'
      i = next + 1
      continue
    }
    if (char === '"' || char === "'") quote = char
    result += char
    i += 1
  }
  return result
}

function lineOf(text: string, offset: number): number {
  let line = 1
  for (let index = 0; index < offset && index < text.length; index += 1) {
    if (text[index] === '\n') line += 1
  }
  return line
}

function markerBefore(text: string, offset: number): boolean {
  const lineStart = text.lastIndexOf('\n', Math.max(0, offset - 1)) + 1
  if (lineStart === 0) return false
  const previousEnd = lineStart - 1
  const previousStart = text.lastIndexOf('\n', Math.max(0, previousEnd - 1)) + 1
  return text.slice(previousStart, previousEnd).trim().startsWith(CADDY_MARKER)
}

/** Первый значимый символ заголовка блока: пробелы и комментарии пропускаем */
function firstCodeIndex(text: string, from: number, to: number): number {
  let i = from
  while (i < to) {
    const char = text[i] ?? ''
    if (/\s/.test(char)) {
      i += 1
      continue
    }
    if (char === '#') {
      const next = text.indexOf('\n', i)
      i = next === -1 ? to : next + 1
      continue
    }
    return i
  }
  return from
}

/** Блоки Caddyfile: сайты, наш сниппет и глобальные настройки */
export function parseCaddyfile(text: string): CaddyBlock[] {
  const blocks: CaddyBlock[] = []
  let quote: string | null = null
  let segmentStart = 0
  let i = 0
  while (i < text.length) {
    const char = text[i] ?? ''
    if (quote !== null) {
      if (char === '\\') {
        i += 2
        continue
      }
      if (char === quote) quote = null
      i += 1
      continue
    }
    if (char === '#') {
      const next = text.indexOf('\n', i)
      i = next === -1 ? text.length : next + 1
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      i += 1
      continue
    }
    if (char !== '{') {
      i += 1
      continue
    }

    const header = stripComments(text.slice(segmentStart, i)).trim()
    const headerStart = firstCodeIndex(text, segmentStart, i)
    const close = findMatchingBrace(text, i)
    if (close === -1) break

    const snippet = /^\(([^)]+)\)$/.exec(header)
    if (snippet !== null) {
      const name = snippet[1] ?? ''
      blocks.push({
        kind: 'snippet',
        address: header,
        name,
        start: headerStart,
        open: i,
        close,
        line: lineOf(text, i),
        marked: markerBefore(text, headerStart),
      })
    } else if (header.length === 0) {
      blocks.push({
        kind: 'global',
        address: '',
        name: null,
        start: headerStart,
        open: i,
        close,
        line: lineOf(text, i),
        marked: false,
      })
    } else {
      blocks.push({
        kind: 'site',
        address: header,
        name: null,
        start: headerStart,
        open: i,
        close,
        line: lineOf(text, i),
        marked: false,
      })
    }
    i = close + 1
    segmentStart = i
  }
  return blocks
}

export function addressHosts(address: string): string[] {
  const result: string[] = []
  for (const raw of address.split(/[\s,]+/)) {
    let value = raw.trim()
    if (value.length === 0) continue
    value = value.replace(/^https?:\/\//i, '')
    const slash = value.indexOf('/')
    if (slash !== -1) value = value.slice(0, slash)
    value = value.replace(/:\d+$/, '')
    if (value.length > 0 && !result.includes(value)) result.push(value)
  }
  return result
}

export function caddySitesForDomain(text: string, domain: string): CaddyBlock[] {
  return parseCaddyfile(text).filter(
    (block) =>
      block.kind === 'site' &&
      addressHosts(block.address).some((host) => matchesDomain(host, domain)),
  )
}

const HEADER_RE =
  /\b(Strict-Transport-Security|X-Content-Type-Options|Referrer-Policy|X-Frame-Options|Content-Security-Policy-Report-Only)\b/i

/** Что уже лежит в сниппете: при повторном fix не теряем прежние директивы */
export function caddySnippetChecks(content: string): string[] {
  return presentItems(content)
}

function presentItems(body: string): string[] {
  const clean = stripComments(body)
  const present: string[] = []
  if (HEADER_RE.test(clean)) present.push('web.headers')
  if (/\bheader\s+-Server\b/i.test(clean) || /(^|\n)\s*-Server\s*(\n|$)/.test(clean)) {
    present.push('web.banner')
  }
  if (/\b@maps\b/i.test(clean) || /path\s+\*\.map\b/i.test(clean)) present.push('web.sourcemaps')
  return present
}

/** Содержимое блока сниппета без маркера */
export function caddySnippetBlock(checks: readonly string[], csp: string): string {
  const lines: string[] = [`(${CADDY_SNIPPET}) {`]
  if (checks.includes('web.headers')) {
    lines.push('    header {')
    lines.push('        Strict-Transport-Security "max-age=31536000; includeSubDomains"')
    lines.push('        X-Content-Type-Options "nosniff"')
    lines.push('        Referrer-Policy "strict-origin-when-cross-origin"')
    lines.push('        X-Frame-Options "SAMEORIGIN"')
    lines.push(`        Content-Security-Policy-Report-Only "${csp.replace(/"/g, '\\"')}"`)
    lines.push('    }')
  }
  if (checks.includes('web.banner')) lines.push('    header -Server')
  if (checks.includes('web.sourcemaps')) {
    lines.push('    @maps path *.map')
    lines.push('    respond @maps 404')
  }
  lines.push('}')
  return lines.join('\n')
}

export function caddySnippetFile(checks: readonly string[], csp: string): string {
  return `${CADDY_MARKER}: сниппет ниже ведёт команда fix, правки внутри него будут перезаписаны\n${caddySnippetBlock(checks, csp)}\n`
}

function blockIndent(text: string, block: CaddyBlock): string {
  const body = text.slice(block.open + 1, block.close)
  for (const line of body.split('\n')) {
    const match = /^([\t ]+)\S/.exec(line)
    if (match !== null) return match[1] ?? '    '
  }
  const headerLineStart = text.lastIndexOf('\n', Math.max(0, block.start - 1)) + 1
  const headerLine = text.slice(headerLineStart, block.start)
  const prefix = /^[\t ]*/.exec(headerLine)?.[0] ?? ''
  return `${prefix}    `
}

function importInsertion(
  text: string,
  block: CaddyBlock,
  indent: string,
): { at: number; text: string } {
  const newline = text.indexOf('\n', block.open + 1)
  if (newline !== -1 && text.slice(block.open + 1, newline).trim().length === 0) {
    return { at: newline + 1, text: `${indent}import ${CADDY_SNIPPET}\n` }
  }
  return { at: block.open + 1, text: `\n${indent}import ${CADDY_SNIPPET}` }
}

export interface CaddyPlanInput {
  domain: string
  checks: readonly string[]
  csp: string
  text: string
}

export interface CaddyPlan {
  edits: FixEdit[]
  skipped: FixSkip[]
}

/** План для Caddyfile: сниппет в начале, import первой строкой блока сайта */
export function planCaddyFix(input: CaddyPlanInput): CaddyPlan {
  const edits: FixEdit[] = []
  const skipped: FixSkip[] = []
  const blocks = parseCaddyfile(input.text)
  const sites = blocks.filter(
    (block) =>
      block.kind === 'site' &&
      addressHosts(block.address).some((host) => matchesDomain(host, input.domain)),
  )

  if (sites.length === 0) {
    for (const checkId of input.checks) {
      skipped.push({
        checkId,
        target: CADDYFILE_PATH,
        reason: 'no-block',
        detail: ru.fix.noServerBlock(input.domain),
      })
    }
    return { edits, skipped }
  }

  const checks = input.checks.filter((id) => {
    if (id !== 'web.ratelimit') return true
    skipped.push({
      checkId: 'web.ratelimit',
      target: CADDYFILE_PATH,
      reason: 'unsupported',
      detail: ru.fix.caddyRatelimit,
    })
    return false
  })

  const manual = new Set<string>()
  for (const site of sites) {
    const present = presentItems(input.text.slice(site.open + 1, site.close))
    for (const id of present) {
      manual.add(id)
      skipped.push({
        checkId: id,
        target: `${CADDYFILE_PATH}:${site.line}`,
        reason: 'already',
        detail: ru.fix.alreadyManual(ru.fix.itemName(id)),
      })
    }
  }

  const snippet = blocks.find(
    (block) => block.kind === 'snippet' && block.name === CADDY_SNIPPET,
  )
  const existingChecks =
    snippet === undefined
      ? []
      : caddySnippetChecks(input.text.slice(snippet.open + 1, snippet.close))
  const wanted = new Set<string>([
    ...existingChecks,
    ...checks.filter((id) => !manual.has(id)),
  ])
  const snippetChecks = [...wanted]
  if (snippetChecks.length === 0) return { edits, skipped }

  const expectedBlock = caddySnippetBlock(snippetChecks, input.csp)

  interface TextOp {
    at: number
    removeTo: number
    text: string
  }
  const operations: TextOp[] = []

  if (snippet === undefined) {
    const global = blocks.find((block) => block.kind === 'global')
    const at = global === undefined ? 0 : global.close + 1
    const addition = caddySnippetFile(snippetChecks, input.csp)
    operations.push({
      at,
      removeTo: at,
      text: at === 0 ? `${addition}\n` : `\n${addition}`,
    })
  } else {
    const current = input.text.slice(snippet.start, snippet.close + 1)
    if (current !== expectedBlock) {
      if (!snippet.marked) {
        for (const checkId of snippetChecks) {
          skipped.push({
            checkId,
            target: `${CADDYFILE_PATH}:${snippet.line}`,
            reason: 'partial',
            detail: ru.fix.foreignSnippet(CADDY_SNIPPET),
          })
        }
        return { edits, skipped }
      }
      operations.push({ at: snippet.start, removeTo: snippet.close + 1, text: expectedBlock })
    }
  }

  for (const site of sites) {
    const body = input.text.slice(site.open + 1, site.close)
    if (/(^|\n)\s*import\s+borodatych-security\s*(\n|$)/.test(stripComments(body))) continue
    const insertion = importInsertion(input.text, site, blockIndent(input.text, site))
    operations.push({ at: insertion.at, removeTo: insertion.at, text: insertion.text })
  }

  if (operations.length === 0) return { edits, skipped }

  let after = input.text
  for (const operation of [...operations].sort((a, b) => b.at - a.at)) {
    after = `${after.slice(0, operation.at)}${operation.text}${after.slice(operation.removeTo)}`
  }
  if (after !== input.text) {
    edits.push({
      path: CADDYFILE_PATH,
      before: input.text,
      after,
      kind: input.text.length === 0 ? 'create' : 'modify',
      summary: ru.fix.summaryCaddy,
    })
  }

  return { edits, skipped }
}
