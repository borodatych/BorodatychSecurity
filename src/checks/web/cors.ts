import { ru } from '../../i18n/ru'
import { auditCors } from '../../parsers/web'
import type { Check } from '../../types'
import { webSession } from '../../web/session'
import { isFailed, requestFailed, webSkip } from './shared'

const FOREIGN_ORIGIN = 'https://borodatych-security.invalid'

export const webCors: Check = {
  id: 'web.cors',
  section: 5,
  severity: 'high',
  async run(ctx) {
    const skip = webSkip(ctx)
    if (skip !== null) return skip
    const session = webSession(ctx)
    if (session === null) {
      return { status: 'skip', findings: [ru.facts.webNoDomain()], fix: 'common.none' }
    }

    const get = await session.get('/', {
      cache: false,
      headers: { origin: FOREIGN_ORIGIN },
    })
    const options = await session.request('OPTIONS', '/', {
      cache: false,
      headers: {
        origin: FOREIGN_ORIGIN,
        'access-control-request-method': 'GET',
      },
    })
    if (isFailed(get) && isFailed(options)) return requestFailed('/', get)

    const audits = [get, options]
      .filter((response) => !isFailed(response))
      .map((response) => auditCors(response.headers, FOREIGN_ORIGIN))
    const risky = audits.filter((audit) => audit.risk === 'fail')
    if (risky.length === 0) {
      return { status: 'ok', findings: [ru.facts.webCorsOk()], fix: 'web.cors' }
    }
    return {
      status: 'fail',
      findings: [
        ru.facts.webCorsOpen(
          risky[0]?.allowOrigin ?? '*',
          risky.some((audit) => audit.credentials),
        ),
      ],
      fix: 'web.cors',
    }
  },
}
