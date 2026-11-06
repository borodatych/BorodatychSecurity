export type Status = 'ok' | 'warn' | 'fail' | 'skip' | 'unknown'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type SectionId = 1 | 2 | 3 | 4 | 5 | 6

/** Результат одной проверки: факты и ключ текста «чем чинить» в i18n */
export interface CheckResult {
  status: Status
  findings: string[]
  fix: string
}

export interface Ctx {
  /** Домен для проверок сайта снаружи (раздел 5), пока только сохраняется */
  domain?: string
  platform: NodeJS.Platform
  now: Date
  env: NodeJS.ProcessEnv
  run: (cmd: string, args?: readonly string[]) => Promise<ExecResult>
  read: (path: string) => Promise<string | null>
  readdir: (path: string) => Promise<string[] | null>
  statMtime: (path: string) => Promise<Date | null>
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
