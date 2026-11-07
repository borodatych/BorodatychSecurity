import type { Status } from '../types'

/** Ответ сайта в виде, пригодном для чистого разбора и тестов */
export interface WebResponseData {
  path: string
  status: number
  body: string
  headers: Record<string, string>
  setCookie?: string[]
}

export type HeaderMap = Readonly<Record<string, string>>

export function headerValue(headers: HeaderMap, name: string): string {
  const lower = name.toLowerCase()
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value
  }
  return ''
}

function normalizeBody(body: string): string {
  return body.replace(/\r\n/g, '\n').trim()
}

/** SPA отдаёт index.html на любой путь: такой ответ — не утечка */
export function isSpaFallback(probe: WebResponseData, baseline: WebResponseData): boolean {
  if (probe.status !== 200 || baseline.status !== 200) return false
  return normalizeBody(probe.body) === normalizeBody(baseline.body)
}

function secretSignature(path: string): RegExp | null {
  if (path === '/.env') return /(?:^|\n)\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/m
  if (path === '/.git/config') return /\[core\]/i
  if (path === '/.git/HEAD') return /^(?:ref:\s+refs\/\S*|[0-9a-f]{40})\s*$/im
  if (path === '/config.json') return /^\s*[{[]/
  if (path === '/.DS_Store') return /\bBud1\b/
  if (path === '/backup.sql') {
    return /(?:CREATE\s+TABLE|INSERT\s+INTO|--\s+(?:MySQL|PostgreSQL)\s+dump|PostgreSQL\s+database\s+dump)/i
  }
  if (path === '/server-status') {
    return /(?:Apache Server Status|Server Version:|Total Accesses:)/i
  }
  if (path === '/phpinfo.php') return /(?:<title>phpinfo|phpinfo\(\))/i
  return null
}

function matchesSecretSignature(path: string, body: string): boolean {
  const signature = secretSignature(path)
  if (signature === null) return false
  if (path === '/config.json') {
    try {
      const data: unknown = JSON.parse(body)
      if (typeof data !== 'object' || data === null || Array.isArray(data)) return false
      const keys = Object.keys(data)
      // JSON-заглушки вида {"error":"not found"} — не конфиг
      return (
        keys.length > 0 &&
        !keys.every((key) => /^(?:error|message|status|detail|code|errors)$/i.test(key))
      )
    } catch {
      return false
    }
  }
  return signature.test(body)
}

export interface SecretLeak {
  path: string
}

/** Сигнатуры содержимого обязательны; ответ сравнивается с несуществующим путём */
export function findSecretLeaks(
  probes: readonly WebResponseData[],
  baseline: WebResponseData,
): SecretLeak[] {
  const leaks: SecretLeak[] = []
  for (const probe of probes) {
    if (probe.status !== 200) continue
    if (isSpaFallback(probe, baseline)) continue
    if (matchesSecretSignature(probe.path, probe.body)) leaks.push({ path: probe.path })
  }
  return leaks
}

export function resolveUrl(reference: string, base: string): string | null {
  try {
    return new URL(reference, base).toString()
  } catch {
    return null
  }
}

/** src скриптов со страницы, только абсолютные http(s) */
export function extractScriptSources(html: string, pageUrl: string): string[] {
  const result: string[] = []
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi
  let match = re.exec(html)
  while (match !== null) {
    const resolved = resolveUrl(match[1] ?? '', pageUrl)
    if (resolved !== null && /^https?:/i.test(resolved) && !result.includes(resolved)) {
      result.push(resolved)
    }
    match = re.exec(html)
  }
  return result
}

/** Ссылки sourceMappingURL из JS */
export function extractSourceMapUrls(js: string, jsUrl: string): string[] {
  const result: string[] = []
  const re = /(?:\/\/[#@]\s*sourceMappingURL=|\/\*[#@]\s*sourceMappingURL=)([^\s*]+)/g
  let match = re.exec(js)
  while (match !== null) {
    const resolved = resolveUrl(match[1] ?? '', jsUrl)
    if (resolved !== null && !result.includes(resolved)) result.push(resolved)
    match = re.exec(js)
  }
  return result
}

/** Тело похоже на карту исходников */
export function looksLikeSourceMap(body: string, contentType = ''): boolean {
  if (/javascript|text\/html/i.test(contentType)) return false
  try {
    const data: unknown = JSON.parse(body)
    if (typeof data !== 'object' || data === null) return false
    const record = data as Record<string, unknown>
    return typeof record.version === 'number' && (typeof record.mappings === 'string' || Array.isArray(record.sources))
  } catch {
    return false
  }
}

export interface HeaderAudit {
  hsts: boolean
  nosniff: boolean
  frame: boolean
  referrer: boolean
  csp: boolean
  /** CSP включён только наблюдением: браузер шлёт отчёты, но ничего не блокирует */
  cspReportOnly: boolean
}

export function auditSecurityHeaders(headers: HeaderMap): HeaderAudit {
  const csp = headerValue(headers, 'content-security-policy')
  return {
    hsts: headerValue(headers, 'strict-transport-security').length > 0,
    nosniff: /nosniff/i.test(headerValue(headers, 'x-content-type-options')),
    frame:
      headerValue(headers, 'x-frame-options').length > 0 ||
      /frame-ancestors/i.test(csp),
    referrer: headerValue(headers, 'referrer-policy').length > 0,
    csp: csp.length > 0,
    cspReportOnly: headerValue(headers, 'content-security-policy-report-only').length > 0,
  }
}

export interface CorsAudit {
  allowOrigin: string | null
  credentials: boolean
  wildcard: boolean
  reflected: boolean
  risk: 'ok' | 'fail'
}

export function auditCors(headers: HeaderMap, origin: string): CorsAudit {
  const allowOrigin = headerValue(headers, 'access-control-allow-origin') || null
  const credentials = /true/i.test(headerValue(headers, 'access-control-allow-credentials'))
  const wildcard = allowOrigin === '*'
  const reflected = allowOrigin !== null && allowOrigin.toLowerCase() === origin.toLowerCase()
  const risk = credentials && (wildcard || reflected) ? 'fail' : 'ok'
  return { allowOrigin, credentials, wildcard, reflected, risk }
}

export interface CookieAudit {
  name: string
  secure: boolean
  httpOnly: boolean
  sameSite: string | null
  session: boolean
  missing: string[]
}

export function parseSetCookie(value: string): CookieAudit {
  const parts = value.split(';').map((part) => part.trim())
  const pair = parts[0] ?? ''
  const name = (pair.split('=')[0] ?? '').trim()
  const attributes = new Map<string, string>()
  for (const part of parts.slice(1)) {
    const eq = part.indexOf('=')
    const key = (eq >= 0 ? part.slice(0, eq) : part).trim().toLowerCase()
    attributes.set(key, eq >= 0 ? part.slice(eq + 1).trim() : '')
  }
  const sameSite = attributes.get('samesite') ?? null
  const secure = attributes.has('secure')
  const httpOnly = attributes.has('httponly')
  const session =
    (!attributes.has('max-age') && !attributes.has('expires')) ||
    /sess|sid|auth|token|jwt/i.test(name)
  const missing: string[] = []
  if (!secure) missing.push('Secure')
  if (!httpOnly) missing.push('HttpOnly')
  if (sameSite === null) missing.push('SameSite')
  else if (sameSite.toLowerCase() === 'none' && !secure) missing.push('Secure для SameSite=None')
  return { name, secure, httpOnly, sameSite, session, missing }
}

/** Проблемные сессионные cookie */
export function auditCookies(values: readonly string[]): CookieAudit[] {
  return values
    .map(parseSetCookie)
    .filter((cookie) => cookie.name.length > 0 && cookie.session && cookie.missing.length > 0)
}

export interface CertificateAudit {
  daysLeft: number
  status: Status
}

export function auditCertificate(validTo: Date, now: Date): CertificateAudit {
  const daysLeft = Math.ceil((validTo.getTime() - now.getTime()) / 86_400_000)
  let status: Status = 'ok'
  if (daysLeft <= 14) status = 'fail'
  else if (daysLeft <= 30) status = 'warn'
  return { daysLeft, status }
}

export interface RateAudit {
  total: number
  tooMany: number
}

export function auditRateLimit(statuses: readonly number[]): RateAudit {
  return {
    total: statuses.length,
    tooMany: statuses.filter((status) => status === 429).length,
  }
}

export interface BannerFinding {
  header: string
  value: string
}

const BANNER_HEADERS = ['server', 'x-powered-by'] as const
const VERSION_RE = /\d+\.\d+/i

export function findVersionBanners(headers: HeaderMap): BannerFinding[] {
  const result: BannerFinding[] = []
  for (const name of BANNER_HEADERS) {
    const value = headerValue(headers, name)
    if (value.length > 0 && VERSION_RE.test(value)) result.push({ header: name, value })
  }
  return result
}
