import { ru } from '../../i18n/ru'
import { findVersionBanners } from '../../parsers/web'
import type { Check } from '../../types'
import { webSession } from '../../web/session'
import { isFailed, requestFailed, webSkip } from './shared'

export const webBanner: Check = {
  id: 'web.banner',
  section: 5,
  severity: 'low',
  async run(ctx) {
    const skip = webSkip(ctx)
    if (skip !== null) return skip
    const session = webSession(ctx)
    if (session === null) {
      return { status: 'skip', findings: [ru.facts.webNoDomain()], fix: 'common.none' }
    }

    const home = await session.get('/')
    if (isFailed(home)) return requestFailed('/', home)
    const banners = findVersionBanners(home.headers)
    if (banners.length === 0) {
      return { status: 'ok', findings: [ru.facts.webBannerNone()], fix: 'web.banner' }
    }
    return {
      status: 'warn',
      findings: banners.map((banner) => ru.facts.webBannerVersion(banner.header, banner.value)),
      fix: 'web.banner',
    }
  },
}
