import type { Stack } from './recipes/types'

export type Status = 'ok' | 'warn' | 'fail' | 'skip' | 'unknown'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type SectionId = 1 | 2 | 3 | 4 | 5 | 6

/** Результат одной проверки: факты и ключ текста «чем чинить» в i18n */
export interface CheckResult {
  status: Status
  findings: string[]
  fix: string
  /** Итоговая важность, если находка подняла базовую важность проверки */
  severity?: Severity
}

/** Рукопожатие TLS, каким его видит проверка: срок сертификата или ошибка */
export interface TlsHandshake {
  validTo: string | null
  error: string | null
}

/** Подменяемое рукопожатие: сайт проводит его через защиту от SSRF */
export type TlsHandshakeFn = (options: {
  host: string
  port: number
  maxVersion?: string
}) => Promise<TlsHandshake>

export interface Ctx {
  /** Домен для проверок сайта снаружи (раздел 5) */
  domain?: string
  platform: NodeJS.Platform
  now: Date
  env: NodeJS.ProcessEnv
  run: (cmd: string, args?: readonly string[]) => Promise<ExecResult>
  read: (path: string) => Promise<string | null>
  readdir: (path: string) => Promise<string[] | null>
  statMtime: (path: string) => Promise<Date | null>
  /** Пути файлов-приманок для проверки ops.canary */
  canaryPaths?: string[]
  /** Запросы сайта снаружи; сайт подставляет fetch с защитой от SSRF */
  fetch?: typeof fetch
  /** Рукопожатие TLS; сайт подставляет своё с проверкой адреса */
  tlsHandshake?: TlsHandshakeFn
}

export interface ExecOk {
  ok: true
  stdout: string
  stderr: string
  code: number | null
}

export interface ExecErr {
  ok: false
  reason: 'missing' | 'denied' | 'timeout' | 'error'
  stdout: string
  stderr: string
  code: number | null
}

export type ExecResult = ExecOk | ExecErr

export interface Check {
  id: string
  section: SectionId
  severity: Severity
  run: (ctx: Ctx) => Promise<CheckResult>
}

export interface CheckReport {
  id: string
  section: SectionId
  severity: Severity
  status: Status
  findings: string[]
  fix: string
}

export interface JsonReport {
  version: string
  host: string
  startedAt: string
  checks: CheckReport[]
  /** Стеки сайта и стартовый CSP, если проверялся домен */
  site?: { stacks: Stack[]; csp: string | null }
}

export const STATUS_RANK: Record<Status, number> = {
  fail: 0,
  warn: 1,
  unknown: 2,
  skip: 3,
  ok: 4,
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}
