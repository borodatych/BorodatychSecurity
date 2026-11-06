import { ru } from '../../i18n/ru'
import { auditCookies } from '../../parsers/web'
import type { Check } from '../../types'
import { webSession } from '../../web/session'
import { isFailed, requestFailed, webSkip } from './shared'

export const webCookies: Check = {
  id: 'web.cookies',
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
    const values = home.setCookie ?? []
    if (values.length === 0) {
      return { status: 'ok', findings: [ru.facts.webCookiesNone()], fix: 'web.cookies' }
    }
    const bad = auditCookies(values)
    if (bad.length === 0) {
      return { status: 'ok', findings: [ru.facts.webCookiesOk()], fix: 'web.cookies' }
    }
    return {
      status: 'warn',
      findings: bad.map((cookie) => ru.facts.webCookieBad(cookie.name, cookie.missing.join(', '))),
      fix: 'web.cookies',
    }
  },
}
