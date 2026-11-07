import { ru } from '../../i18n/ru'
import { auditSecurityHeaders } from '../../parsers/web'
import type { Check } from '../../types'
import { webSession } from '../../web/session'
import { isFailed, requestFailed, webSkip } from './shared'

export const webHeaders: Check = {
  id: 'web.headers',
  section: 5,
  severity: 'medium',
  async run(ctx) {
    const skip = webSkip(ctx)
    if (skip !== null) return skip
    const session = webSession(ctx)
    if (session === null) {
      return { status: 'skip', findings: [ru.facts.webNoDomain()], fix: 'common.none' }
    }

    const home = await session.get('/')
    if (isFailed(home)) return requestFailed('/', home)
    const audit = auditSecurityHeaders(home.headers)
    const missing: string[] = []
    if (!audit.hsts) missing.push('Strict-Transport-Security')
    if (!audit.nosniff) missing.push('X-Content-Type-Options: nosniff')
    if (!audit.frame) missing.push('X-Frame-Options или frame-ancestors')
    if (!audit.referrer) missing.push('Referrer-Policy')
    if (!audit.csp && !audit.cspReportOnly) missing.push('Content-Security-Policy')
    // Report-Only — честный первый шаг, но защиты ещё нет: проверка остаётся предупреждением с подсказкой
    const reportOnly = !audit.csp && audit.cspReportOnly
    if (missing.length === 0 && !reportOnly) {
      return { status: 'ok', findings: [ru.facts.webHeadersOk()], fix: 'web.headers' }
    }
    return {
      status: 'warn',
      findings: [
        ...missing.map((name) => ru.facts.webHeaderMissing(name)),
        ...(reportOnly ? [ru.facts.webCspReportOnly()] : []),
      ],
      fix: 'web.headers',
    }
  },
}
