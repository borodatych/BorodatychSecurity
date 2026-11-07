import { ru } from '../i18n/ru'
import type { FixEdit, FixSkip } from './types'

/** Наш сниппет с директивами уровня server */
export const NGINX_SNIPPET_PATH = '/etc/nginx/snippets/borodatych-security.conf'
/** Зона лимита живёт в http, поэтому отдельным файлом в conf.d */
export const NGINX_RATELIMIT_PATH = '/etc/nginx/conf.d/borodatych-security-ratelimit.conf'
/** Маркер: по нему узнаём свой файл и не трогаем чужой */
export const NGINX_MARKER = '# borodatych-security'
/** Имя зоны лимита */
export const NGINX_ZONE = 'borodatych_security'
/** Строка include, которую вставляем после server_name */
export const NGINX_INCLUDE = `include ${NGINX_SNIPPET_PATH};  # borodatych-security`

export interface NginxFile {
  path: string
  text: string
}

export interface NginxDirective {
  name: string
  args: string
  start: number
  /** Индекс `;` для обычной директивы или `}` для блока */
  end: number
  block: boolean
  blockOpen: number | null
  blockClose: number | null
}

export interface NginxServerBlock {
  file: string
  start: number
  open: number
  close: number
  names: string[]
  listens: string[]
  hasInclude: boolean
  /** id проверок, директивы которых уже заданы в блоке вручную */
  present: string[]
  serverNameStart: number | null
  serverNameLineEnd: number | null
  line: number
}

interface RawBlock {
  start: number
  open: number
  close: number
}

function isWordChar(char: string): boolean {
  return /[A-Za-z0-9_.-]/.test(char)
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

function findBlocks(text: string, keyword: string): RawBlock[] {
  const blocks: RawBlock[] = []
  let quote: string | null = null
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
    if (!isWordChar(char)) {
      i += 1
      continue
    }

    let end = i + 1
    while (end < text.length && isWordChar(text[end] ?? '')) end += 1
    const word = text.slice(i, end)
    if (word === keyword) {
      let next = end
      while (next < text.length && /\s/.test(text[next] ?? '')) next += 1
      if (text[next] === '{') {
        const close = findMatchingBrace(text, next)
        if (close !== -1) {
          blocks.push({ start: i, open: next, close })
          i = close + 1
          continue
        }
      }
    }
    i = end
  }
  return blocks
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

function words(value: string): string[] {
  return value
    .split(/\s+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
}

/** Директивы на одном уровне вложенности внутри блока */
export function parseDirectives(
  text: string,
  from: number,
  to: number,
): NginxDirective[] {
  const directives: NginxDirective[] = []
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
    if (char === '}') break

    const start = i
    let nameEnd = i
    while (nameEnd < to && isWordChar(text[nameEnd] ?? '')) nameEnd += 1
    if (nameEnd === start) {
      i += 1
      continue
    }
    const name = text.slice(start, nameEnd)

    let quote: string | null = null
    let cursor = nameEnd
    let terminator = -1
    let terminatorChar = ''
    while (cursor < to) {
      const current = text[cursor] ?? ''
      if (quote !== null) {
        if (current === '\\') {
          cursor += 2
          continue
        }
        if (current === quote) quote = null
        cursor += 1
        continue
      }
      if (current === '#') {
        const next = text.indexOf('\n', cursor)
        cursor = next === -1 ? to : next + 1
        continue
      }
      if (current === '"' || current === "'") {
        quote = current
        cursor += 1
        continue
      }
      if (current === ';' || current === '{' || current === '}') {
        terminator = cursor
        terminatorChar = current
        break
      }
      cursor += 1
    }
    if (terminator === -1) break

    const args = stripComments(text.slice(nameEnd, terminator)).trim()
    if (terminatorChar === ';') {
      directives.push({
        name,
        args,
        start,
        end: terminator,
        block: false,
        blockOpen: null,
        blockClose: null,
      })
      i = terminator + 1
      continue
    }
    if (terminatorChar === '}') break

    const close = findMatchingBrace(text, terminator)
    directives.push({
      name,
      args,
      start,
      end: close === -1 ? to : close,
      block: true,
      blockOpen: terminator,
      blockClose: close === -1 ? null : close,
    })
    if (close === -1) break
    i = close + 1
  }
  return directives
}

function lineOf(text: string, offset: number): number {
  let line = 1
  for (let index = 0; index < offset && index < text.length; index += 1) {
    if (text[index] === '\n') line += 1
  }
  return line
}

/** Точное имя или wildcard-родитель: *.example.ru закрывает и сам домен, и поддомены */
export function matchesDomain(name: string, domain: string): boolean {
  const clean = name.trim().toLowerCase().replace(/\.$/, '')
  const target = domain.toLowerCase()
  if (clean.length === 0 || clean.startsWith('~')) return false
  if (clean === target) return true
  if (clean.startsWith('*.')) {
    const suffix = clean.slice(2)
    return target === suffix || target.endsWith(`.${suffix}`)
  }
  if (clean.startsWith('.')) {
    const suffix = clean.slice(1)
    return target === suffix || target.endsWith(`.${suffix}`)
  }
  return false
}

function listens443(listen: string): boolean {
  return words(listen).some((token) => token === '443' || token.endsWith(':443'))
}

const HEADER_NAMES = new Set([
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'x-frame-options',
  'content-security-policy-report-only',
])

function managedItems(directives: readonly NginxDirective[]): string[] {
  const present: string[] = []
  const add = (id: string): void => {
    if (!present.includes(id)) present.push(id)
  }
  for (const directive of directives) {
    if (directive.name === 'add_header') {
      const header = (words(directive.args)[0] ?? '').toLowerCase()
      if (HEADER_NAMES.has(header)) add('web.headers')
    }
    if (directive.name === 'server_tokens') add('web.banner')
    if (directive.name === 'limit_req') add('web.ratelimit')
    if (directive.name === 'location' && /\.map\b/.test(directive.args)) add('web.sourcemaps')
  }
  return present
}

/** Server-блоки файла: имена, listen, include и уже заданные директивы */
export function parseServers(file: NginxFile): NginxServerBlock[] {
  const servers: NginxServerBlock[] = []
  for (const raw of findBlocks(file.text, 'server')) {
    const directives = parseDirectives(file.text, raw.open + 1, raw.close)
    const names: string[] = []
    const listens: string[] = []
    let hasInclude = false
    let serverNameStart: number | null = null
    let serverNameLineEnd: number | null = null
    for (const directive of directives) {
      if (directive.name === 'server_name') {
        names.push(...words(directive.args))
        if (serverNameLineEnd === null) {
          serverNameStart = directive.start
          const newline = file.text.indexOf('\n', directive.end)
          serverNameLineEnd = newline === -1 ? directive.end + 1 : newline + 1
        }
      }
      if (directive.name === 'listen') listens.push(directive.args)
      if (directive.name === 'include' && directive.args.includes('borodatych-security')) {
        hasInclude = true
      }
    }
    servers.push({
      file: file.path,
      start: raw.start,
      open: raw.open,
      close: raw.close,
      names,
      listens,
      hasInclude,
      present: managedItems(directives),
      serverNameStart,
      serverNameLineEnd,
      line: lineOf(file.text, raw.start),
    })
  }
  return servers
}

/** Что уже лежит в нашем сниппете: при повторном fix не теряем прежние директивы */
export function nginxSnippetChecks(content: string): string[] {
  return managedItems(parseDirectives(content, 0, content.length))
}

export function serversForDomain(file: NginxFile, domain: string): NginxServerBlock[] {
  return parseServers(file).filter((server) =>
    server.names.some((name) => matchesDomain(name, domain)),
  )
}

/** В http есть include conf.d/*.conf — тогда зону лимита можно положить отдельным файлом */
export function httpIncludesConfD(files: readonly NginxFile[]): boolean {
  for (const file of files) {
    for (const raw of findBlocks(file.text, 'http')) {
      const directives = parseDirectives(file.text, raw.open + 1, raw.close)
      for (const directive of directives) {
        if (directive.name !== 'include') continue
        // Наш файл должен реально попасть в http: нужен conf.d/*.conf или точный путь
        if (
          directive.args.includes('conf.d/*.conf') ||
          directive.args.includes('conf.d/*') ||
          directive.args.includes(NGINX_RATELIMIT_PATH)
        ) {
          return true
        }
      }
    }
  }
  return false
}

/** Разбор вывода `nginx -T`: только пути файлов, содержимое читаем отдельно */
export function parseNginxDump(dump: string): string[] {
  const paths: string[] = []
  for (const line of dump.split('\n')) {
    const match = /^# configuration file (.+):$/.exec(line)
    if (match !== null) {
      const path = match[1]
      if (path !== undefined && !paths.includes(path)) paths.push(path)
    }
  }
  return paths
}

function nginxQuote(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

/** Содержимое нашего сниппета: только выбранные проверки, CSP в Report-Only */
export function nginxSnippetContent(
  checks: readonly string[],
  csp: string,
  ratelimitReady: boolean,
): string {
  const lines: string[] = [
    `${NGINX_MARKER}: файл создан командой fix, ручные правки будут перезаписаны`,
  ]
  if (checks.includes('web.headers')) {
    lines.push(
      'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
      'add_header X-Content-Type-Options "nosniff" always;',
      'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
      'add_header X-Frame-Options "SAMEORIGIN" always;',
      `add_header Content-Security-Policy-Report-Only "${nginxQuote(csp)}" always;`,
    )
  }
  if (checks.includes('web.banner')) lines.push('server_tokens off;')
  if (checks.includes('web.sourcemaps')) {
    lines.push('location ~* \\.map$ {', '    return 404;', '}')
  }
  if (checks.includes('web.ratelimit') && ratelimitReady) {
    lines.push(`limit_req zone=${NGINX_ZONE} burst=20 nodelay;`, 'limit_req_status 429;')
  }
  if (lines.length === 1) return ''
  return `${lines.join('\n')}\n`
}

/** Файл зоны лимита: limit_req_zone допустим только в http */
export function nginxRatelimitContent(): string {
  return (
    `${NGINX_MARKER}: зона лимита запросов\n` +
    `limit_req_zone $binary_remote_addr zone=${NGINX_ZONE}:10m rate=30r/m;\n`
  )
}

function lineIndent(text: string, offset: number): string {
  const lineStart = text.lastIndexOf('\n', Math.max(0, offset - 1)) + 1
  const prefix = text.slice(lineStart, offset)
  const match = /^[\t ]*/.exec(prefix)
  return match?.[0] ?? ''
}

export interface NginxPlanInput {
  domain: string
  checks: readonly string[]
  csp: string
  files: readonly NginxFile[]
  httpIncludesConfD: boolean
  snippetBefore: string | null
  ratelimitBefore: string | null
}

export interface NginxPlan {
  edits: FixEdit[]
  skipped: FixSkip[]
}

function planSnippetFile(
  expected: string,
  before: string | null,
): { edit: FixEdit | null; usable: boolean } {
  if (before === null) {
    return {
      edit: {
        path: NGINX_SNIPPET_PATH,
        before: null,
        after: expected,
        kind: 'create',
        summary: ru.fix.summarySnippet,
      },
      usable: true,
    }
  }
  if (before === expected) return { edit: null, usable: true }
  if (before.includes(NGINX_MARKER)) {
    return {
      edit: {
        path: NGINX_SNIPPET_PATH,
        before,
        after: expected,
        kind: 'modify',
        summary: ru.fix.summarySnippet,
      },
      usable: true,
    }
  }
  return { edit: null, usable: false }
}

/** План для nginx: сниппет, include после server_name, зона лимита */
export function planNginxFix(input: NginxPlanInput): NginxPlan {
  const edits: FixEdit[] = []
  const skipped: FixSkip[] = []

  const targets: NginxServerBlock[] = []
  for (const file of input.files) {
    const matched = serversForDomain(file, input.domain)
    const withTls = matched.filter((server) => server.listens.some(listens443))
    targets.push(...(withTls.length > 0 ? withTls : matched))
  }

  if (targets.length === 0) {
    for (const checkId of input.checks) {
      skipped.push({
        checkId,
        target: 'nginx',
        reason: 'no-block',
        detail: ru.fix.noServerBlock(input.domain),
      })
    }
    return { edits, skipped }
  }

  // Пункт, который где-то уже задан вручную, не кладём в общий сниппет
  const manual = new Set<string>()
  for (const server of targets) {
    for (const id of server.present) manual.add(id)
  }
  for (const server of targets) {
    for (const id of server.present) {
      const name = ru.fix.itemName(id)
      skipped.push({
        checkId: id,
        target: `${server.file}:${server.line}`,
        reason: 'already',
        detail: ru.fix.alreadyManual(name),
      })
    }
  }

  const snippetBefore = input.snippetBefore ?? ''
  const existingSnippetChecks =
    snippetBefore.length > 0 && snippetBefore.includes(NGINX_MARKER)
      ? nginxSnippetChecks(snippetBefore)
      : []
  const ratelimitWanted =
    input.checks.includes('web.ratelimit') || existingSnippetChecks.includes('web.ratelimit')

  let ratelimitReady = false
  let ratelimitEdit: FixEdit | null = null
  if (ratelimitWanted && !manual.has('web.ratelimit')) {
    if (!input.httpIncludesConfD) {
      skipped.push({
        checkId: 'web.ratelimit',
        target: 'nginx',
        reason: 'no-conf-d',
        detail: ru.fix.noConfD,
      })
    } else {
      const expected = nginxRatelimitContent()
      const before = input.ratelimitBefore
      if (before === null) {
        ratelimitEdit = {
          path: NGINX_RATELIMIT_PATH,
          before: null,
          after: expected,
          kind: 'create',
          summary: ru.fix.summaryRatelimit,
        }
        ratelimitReady = true
      } else if (before === expected) {
        ratelimitReady = true
      } else if (before.includes(NGINX_MARKER)) {
        ratelimitEdit = {
          path: NGINX_RATELIMIT_PATH,
          before,
          after: expected,
          kind: 'modify',
          summary: ru.fix.summaryRatelimit,
        }
        ratelimitReady = true
      } else {
        skipped.push({
          checkId: 'web.ratelimit',
          target: NGINX_RATELIMIT_PATH,
          reason: 'partial',
          detail: ru.fix.foreignFile(NGINX_RATELIMIT_PATH),
        })
      }
    }
  }

  // Прежние директивы сниппета сохраняем, новые ручные пункты не добавляем
  const wanted = new Set<string>([
    ...existingSnippetChecks,
    ...input.checks.filter((id) => !manual.has(id)),
  ])
  const snippetChecks = [...wanted].filter(
    (id) => id !== 'web.ratelimit' || ratelimitReady,
  )
  const expectedSnippet = nginxSnippetContent(snippetChecks, input.csp, ratelimitReady)

  let snippetUsable = true
  if (expectedSnippet.length > 0) {
    const planned = planSnippetFile(expectedSnippet, input.snippetBefore)
    snippetUsable = planned.usable
    if (planned.edit !== null) edits.push(planned.edit)
    if (!planned.usable) {
      for (const checkId of snippetChecks) {
        skipped.push({
          checkId,
          target: NGINX_SNIPPET_PATH,
          reason: 'partial',
          detail: ru.fix.foreignFile(NGINX_SNIPPET_PATH),
        })
      }
    }
  } else {
    snippetUsable = false
  }

  // Зону лимита создаём только вместе с limit_req в сниппете
  if (ratelimitEdit !== null) {
    if (snippetUsable && snippetChecks.includes('web.ratelimit')) {
      edits.push(ratelimitEdit)
    } else {
      skipped.push({
        checkId: 'web.ratelimit',
        target: NGINX_RATELIMIT_PATH,
        reason: 'partial',
        detail: ru.fix.snippetBlocked,
      })
    }
  }

  if (snippetUsable && expectedSnippet.length > 0) {
    const insertions = new Map<string, { at: number; text: string }[]>()
    for (const server of targets) {
      if (server.hasInclude) continue
      if (server.serverNameLineEnd === null) {
        for (const checkId of snippetChecks) {
          skipped.push({
            checkId,
            target: `${server.file}:${server.line}`,
            reason: 'no-block',
            detail: ru.fix.noServerName,
          })
        }
        continue
      }
      const file = input.files.find((item) => item.path === server.file)
      if (file === undefined) continue
      const indent =
        server.serverNameStart === null
          ? '    '
          : lineIndent(file.text, server.serverNameStart)
      const newline = file.text.indexOf('\n', server.serverNameLineEnd)
      const insertion =
        newline === -1
          ? { at: file.text.length, text: `\n${indent}${NGINX_INCLUDE}` }
          : { at: newline + 1, text: `${indent}${NGINX_INCLUDE}\n` }
      const list = insertions.get(server.file) ?? []
      list.push(insertion)
      insertions.set(server.file, list)
    }

    for (const [path, list] of insertions) {
      const file = input.files.find((item) => item.path === path)
      if (file === undefined) continue
      let after = file.text
      for (const insertion of [...list].sort((a, b) => b.at - a.at)) {
        after = `${after.slice(0, insertion.at)}${insertion.text}${after.slice(insertion.at)}`
      }
      if (after !== file.text) {
        edits.push({
          path,
          before: file.text,
          after,
          kind: 'modify',
          summary: ru.fix.summaryInclude,
        })
      }
    }
  }

  return { edits, skipped }
}
