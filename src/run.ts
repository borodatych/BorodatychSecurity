import { CliError } from './args'
import { ru } from './i18n/ru'
import { redactSecrets } from './parsers/system'
import type { Check, CheckReport, Ctx } from './types'

export interface Selection {
  only?: string[]
  skip?: string[]
}

/** Выбор проверок; неизвестный id — ошибка CLI */
export function selectChecks(all: readonly Check[], selection: Selection): Check[] {
  const known = new Set(all.map((check) => check.id))
  const requested = [...(selection.only ?? []), ...(selection.skip ?? [])]
  const unknown = requested.filter((id) => !known.has(id))
  if (unknown.length > 0) {
    throw new CliError(ru.report.noChecksFor([...new Set(unknown)].join(', ')))
  }

  let selected = [...all]
  if (selection.only !== undefined) {
    const only = new Set(selection.only)
    selected = selected.filter((check) => only.has(check.id))
  }
  if (selection.skip !== undefined) {
    const skip = new Set(selection.skip)
    selected = selected.filter((check) => !skip.has(check.id))
  }
  return selected
}

/** Последовательный запуск; упавшая проверка не роняет CLI */
export async function runChecks(ctx: Ctx, selected: readonly Check[]): Promise<CheckReport[]> {
  const reports: CheckReport[] = []
  for (const check of selected) {
    try {
      const result = await check.run(ctx)
      reports.push({
        id: check.id,
        section: check.section,
        severity: result.severity ?? check.severity,
        status: result.status,
        findings: result.findings.map(redactSecrets),
        fix: result.fix,
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      reports.push({
        id: check.id,
        section: check.section,
        severity: check.severity,
        status: 'unknown',
        findings: [redactSecrets(ru.facts.commandFailed(check.id, message.slice(0, 200)))],
        fix: 'common.sudo',
      })
    }
  }
  return reports
}
