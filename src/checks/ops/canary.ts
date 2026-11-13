import { ru } from '../../i18n/ru'
import { parseStatMode } from '../../parsers/system'
import type { Check, Status } from '../../types'
import { isLinux, skipped } from '../shared'

/** Приманку читает только root: иначе её найдёт и тронет любой процесс, и датчик сработает впустую */
const CANARY_MODE = '600'
const CANARY_OWNER = 'root:root'

/**
 * Датчик проникновения: файлы-приманки с фейковыми ключами
 * Изнутри не узнать, настоящий ли маячок и доходят ли письма, поэтому без путей итог — unknown с подсказкой
 * Содержимое приманки не читается: проверке хватает того, что файл на месте и закрыт
 */
export const opsCanary: Check = {
  id: 'ops.canary',
  section: 6,
  severity: 'low',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())
    const paths = ctx.canaryPaths ?? []
    if (paths.length === 0) {
      return { status: 'unknown', findings: [ru.facts.canaryNotConfigured()], fix: 'ops.canary' }
    }

    const findings: string[] = []
    const statuses: Status[] = []
    for (const path of paths) {
      const result = await ctx.run('stat', ['-c', '%a %U:%G', '--', path])
      if (!result.ok) {
        if (result.reason === 'denied' || result.reason === 'missing' || result.reason === 'timeout') {
          findings.push(ru.facts.canaryUnchecked(path))
          statuses.push('unknown')
        } else {
          findings.push(ru.facts.canaryAbsent(path))
          statuses.push('fail')
        }
        continue
      }
      const mode = parseStatMode(result.stdout)
      if (mode === null) {
        findings.push(ru.facts.canaryUnchecked(path))
        statuses.push('unknown')
      } else if (mode.mode !== CANARY_MODE || mode.owner !== CANARY_OWNER) {
        findings.push(ru.facts.canaryOpen(path, mode.mode, mode.owner))
        statuses.push('warn')
      } else {
        findings.push(ru.facts.canaryOk(path))
      }
    }

    const status = statuses.includes('fail')
      ? 'fail'
      : statuses.includes('warn')
        ? 'warn'
        : statuses.includes('unknown')
          ? 'unknown'
          : 'ok'
    return { status, findings, fix: 'ops.canary' }
  },
}
