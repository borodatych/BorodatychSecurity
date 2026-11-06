import { ru } from '../../i18n/ru'
import {
  extractScriptSources,
  extractSourceMapUrls,
  headerValue,
  looksLikeSourceMap,
} from '../../parsers/web'
import type { Check } from '../../types'
import { webSession } from '../../web/session'
import { isFailed, requestFailed, webSkip } from './shared'

const MAX_SCRIPTS = 6
const MAX_MAPS = 6

export const webSourcemaps: Check = {
  id: 'web.sourcemaps',
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
    const pageUrl = `${session.origin}/`
    const scripts = extractScriptSources(home.body, pageUrl)
      .filter((source) => source.startsWith(session.origin))
      .slice(0, MAX_SCRIPTS)

    const exposed: string[] = []
    let mapsFetched = 0
    for (const script of scripts) {
      const js = await session.get(script)
      if (isFailed(js)) continue
      for (const map of extractSourceMapUrls(js.body, script)) {
        if (!map.startsWith(session.origin) || mapsFetched >= MAX_MAPS) continue
        mapsFetched += 1
        const response = await session.get(map)
        if (isFailed(response) || response.status !== 200) continue
        const contentType = headerValue(response.headers, 'content-type')
        if (looksLikeSourceMap(response.body, contentType) && !exposed.includes(map)) {
          exposed.push(map)
        }
      }
    }

    if (exposed.length === 0) {
      return { status: 'ok', findings: [ru.facts.webSourceMapsNone()], fix: 'web.sourcemaps' }
    }
    return {
      status: 'fail',
      findings: exposed.map((url) => ru.facts.webSourceMapLeak(url)),
      fix: 'web.sourcemaps',
    }
  },
}
