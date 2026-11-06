import { ru } from '../../i18n/ru'
import { auditRateLimit } from '../../parsers/web'
import type { Check } from '../../types'
import { webSession, type WebResult } from '../../web/session'
import { requestFailed, webSkip } from './shared'

const REQUESTS = 30

export const webRatelimit: Check = {
  id: 'web.ratelimit',
  section: 5,
  severity: 'low',
  async run(ctx) {
    const skip = webSkip(ctx)
    if (skip !== null) return skip
    const session = webSession(ctx)
    if (session === null) {
      return { status: 'skip', findings: [ru.facts.webNoDomain()], fix: 'common.none' }
    }

    const statuses: number[] = []
    let lastFailed: WebResult | null = null
    for (let index = 0; index < REQUESTS; index += 1) {
      // Пауза 0: запросы идут подряд, лимит должен сработать.
      const response = await session.get('/', { cache: false })
      if (response.error !== null || response.status === 0) {
        lastFailed = response
        if (response.error === 'request budget exhausted') break
        continue
      }
      statuses.push(response.status)
    }
    if (statuses.length === 0 && lastFailed !== null) return requestFailed('/', lastFailed)

    const audit = auditRateLimit(statuses)
    if (audit.tooMany === 0) {
      return {
        status: 'warn',
        findings: [ru.facts.webRateLimitNone(audit.total)],
        fix: 'web.ratelimit',
      }
    }
    return {
      status: 'ok',
      findings: [ru.facts.webRateLimitHit(audit.tooMany, audit.total)],
      fix: 'web.ratelimit',
    }
  },
}
