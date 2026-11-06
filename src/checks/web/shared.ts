import { ru } from '../../i18n/ru'
import type { CheckResult, Ctx } from '../../types'
import type { WebResult } from '../../web/session'
import { skipped } from '../shared'

/** Без --domain все web.* — skip */
export function webSkip(ctx: Ctx): CheckResult | null {
  return ctx.domain === undefined ? skipped(ru.facts.webNoDomain()) : null
}

export function requestFailed(what: string, response: WebResult): CheckResult {
  const detail = response.error ?? `HTTP ${String(response.status)}`
  return {
    status: 'unknown',
    findings: [ru.facts.webRequestFailed(what, detail)],
    fix: 'common.network',
  }
}

export function isFailed(response: WebResult): boolean {
  return response.error !== null || response.status === 0
}
