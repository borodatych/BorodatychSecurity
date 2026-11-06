import { ru } from '../i18n/ru'
import {
  SEVERITY_RANK,
  STATUS_RANK,
  type CheckReport,
  type JsonReport,
  type Status,
} from '../types'

const ANSI: Record<Status, string> = {
  fail: '\u001b[31m',
  warn: '\u001b[33m',
  unknown: '\u001b[35m',
  skip: '\u001b[90m',
  ok: '\u001b[32m',
}
const RESET = '\u001b[0m'

export interface TextOptions {
  color: boolean
}

function label(status: Status, color: boolean): string {
  const text = ru.status[status] ?? status
  return color ? `${ANSI[status]}[${text}]${RESET}` : `[${text}]`
}

function sortChecks(checks: readonly CheckReport[]): CheckReport[] {
  return [...checks].sort((a, b) => {
    const byStatus = STATUS_RANK[a.status] - STATUS_RANK[b.status]
    if (byStatus !== 0) return byStatus
    return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
  })
}

function countStatuses(checks: readonly CheckReport[]): Record<string, number> {
  const counts: Record<string, number> = { fail: 0, warn: 0, unknown: 0, skip: 0, ok: 0 }
  for (const check of checks) counts[check.status] = (counts[check.status] ?? 0) + 1
  return counts
}

function checkTitle(check: CheckReport): string {
  return ru.checks[check.id]?.title ?? check.id
}

function renderCheck(check: CheckReport, color: boolean, lines: string[]): void {
  lines.push(`  ${label(check.status, color)} ${check.id} — ${checkTitle(check)}`)
  for (const finding of check.findings) lines.push(`    ${ru.report.finding(finding)}`)
  if (check.status !== 'ok') {
    const problem = ru.checks[check.id]?.problem
    if (problem !== undefined) lines.push(`    ${ru.report.problemLabel(problem)}`)
    lines.push(`    ${ru.report.fixLabel(check.fix)}`)
  }
}

/** Текстовый отчёт: сводка, худшие, затем группы по разделам */
export function renderText(report: JsonReport, options: TextOptions): string {
  const lines: string[] = []
  lines.push(`${ru.report.title} ${report.version}`)
  lines.push(ru.report.host(report.host))
  lines.push(ru.report.startedAt(report.startedAt))
  lines.push(ru.report.summary(countStatuses(report.checks)))

  if (report.checks.length === 0) {
    lines.push('')
    lines.push(ru.report.noChecks)
    return lines.join('\n')
  }

  const worst = sortChecks(report.checks).filter(
    (check) => check.status === 'fail' || check.status === 'warn',
  )
  if (worst.length > 0) {
    lines.push('')
    lines.push(ru.report.worst)
    for (const check of worst) {
      lines.push(`  ${label(check.status, options.color)} ${check.id} — ${checkTitle(check)}`)
    }
  }

  const sections = [...new Set(report.checks.map((check) => check.section))].sort((a, b) => a - b)
  for (const section of sections) {
    lines.push('')
    lines.push(`${String(section)}. ${ru.sections[section] ?? String(section)}`)
    for (const check of sortChecks(report.checks.filter((item) => item.section === section))) {
      renderCheck(check, options.color, lines)
    }
  }
  return lines.join('\n')
}
