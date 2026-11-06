import { ru } from '../../i18n/ru'
import { findSecretLeaks, type WebResponseData } from '../../parsers/web'
import type { Check } from '../../types'
import { webSession, type WebResult } from '../../web/session'
import { isFailed, requestFailed, webSkip } from './shared'

const PATHS = [
  '/.env',
  '/.git/config',
  '/.git/HEAD',
  '/config.json',
  '/.DS_Store',
  '/backup.sql',
  '/server-status',
  '/phpinfo.php',
]

const BASELINE_PATH = '/.borodatych-security-missing'

export const webSecrets: Check = {
  id: 'web.secrets',
  section: 5,
  severity: 'critical',
  async run(ctx) {
    const skip = webSkip(ctx)
    if (skip !== null) return skip
    const session = webSession(ctx)
    if (session === null) {
      return { status: 'skip', findings: [ru.facts.webNoDomain()], fix: 'common.none' }
    }

    const baseline = await session.get(BASELINE_PATH)
    if (isFailed(baseline)) return requestFailed(BASELINE_PATH, baseline)

    const probes: WebResponseData[] = []
    let failed: WebResult | null = null
    for (const path of PATHS) {
      const response = await session.get(path)
      if (isFailed(response)) {
        failed = failed ?? response
        continue
      }
      probes.push(response)
    }
    if (probes.length === 0 && failed !== null) return requestFailed(PATHS[0] ?? '/', failed)

    const leaks = findSecretLeaks(probes, baseline)
    if (leaks.length === 0) {
      return { status: 'ok', findings: [ru.facts.webSecretsNone()], fix: 'web.secrets' }
    }
    return {
      status: 'fail',
      findings: leaks.map((leak) => ru.facts.webSecretLeak(leak.path)),
      fix: 'web.secrets',
    }
  },
}
