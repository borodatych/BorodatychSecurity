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

/** Описания платных инструментов для модели: по-английски, кратко, с обещанием «только чтение» */
export const toolDescriptions = {
  fixPlan:
    'Requires access to the domain: a free slot or a paid pass; the user signs in with the CLI ' +
    '(`npx @borodatych/security login`). Runs the read-only external website audit and returns an ' +
    'ordered repair plan: only fail and warn checks, fail first, then by severity descending. Each ' +
    'step has the check id, title, problem, findings and a ready recipe rendered for the detected ' +
    'stack (steps, config snippet, verify command, risks and other available stacks). This tool only ' +
    'reads: fix only after the user agrees; the tool itself never changes the server.',
  getRecipe:
    'Free, no sign-in needed. Returns the repair recipe for one check id: steps, a config snippet ' +
    'for the requested or detected stack, verify command and risks. domain is optional and only fills ' +
    'in placeholders. Use list_checks first to pick a known id. Read-only: nothing is applied.',
  verifyFix:
    'Requires access to the domain. Re-runs one website check (section 5) against the domain after ' +
    'the user applied a fix and returns status, findings and fixed=true only when the check is ok. ' +
    'Server checks are not supported here: use audit_server on the server itself. Read-only.',
} as const

export const toolTitles = {
  fixPlan: 'План починки',
  getRecipe: 'Рецепт починки',
  verifyFix: 'Проверить починку',
} as const
