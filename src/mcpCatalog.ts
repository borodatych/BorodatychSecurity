import { fixText, ru } from './i18n/ru'
import { checks as registry } from './registry'
import type { SectionId, Severity } from './types'

/** Справка по проверке для explain_check и list_checks */
export interface CheckInfo {
  id: string
  section: SectionId
  sectionTitle: string
  severity: Severity
  title: string
  how: string
  problem: string
  fix: string
}

const byId = new Map(registry.map((check) => [check.id, check]))

export function knownCheckIds(): string[] {
  return registry.map((check) => check.id)
}

export function checkInfo(id: string): CheckInfo | null {
  const check = byId.get(id)
  if (check === undefined) return null
  const text = ru.checks[check.id]
  return {
    id: check.id,
    section: check.section,
    sectionTitle: ru.sections[check.section] ?? String(check.section),
    severity: check.severity,
    title: text?.title ?? check.id,
    how: ru.how[check.id] ?? '',
    problem: text?.problem ?? '',
    fix: fixText(check.id),
  }
}

export function listCheckInfo(): CheckInfo[] {
  return registry.flatMap((check) => {
    const info = checkInfo(check.id)
    return info === null ? [] : [info]
  })
}
