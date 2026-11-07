import { fixText } from '../i18n/ru'
import type { Stack } from '../recipes/types'
import type { CheckReport, JsonReport, Status } from '../types'

/** Стабильная схема отчёта для агентов и будущего MCP */
export function buildJsonReport(
  version: string,
  host: string,
  startedAt: string,
  checks: readonly CheckReport[],
  site?: { stacks: Stack[]; csp: string | null },
): JsonReport {
  return {
    version,
    host,
    startedAt,
    checks: checks.map((check) => ({
      id: check.id,
      section: check.section,
      severity: check.severity,
      status: check.status,
      findings: [...check.findings],
      fix: fixText(check.fix),
    })),
    ...(site === undefined ? {} : { site }),
  }
}

/** 0 — нет fail, 1 — есть fail */
export function exitCodeFor(checks: readonly { status: Status }[]): 0 | 1 {
  return checks.some((check) => check.status === 'fail') ? 1 : 0
}
