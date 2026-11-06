import { ru } from '../../i18n/ru'
import { evaluateOsSupport, parseOsRelease } from '../../parsers/os'
import type { Check } from '../../types'
import { isLinux, skipped } from '../shared'

export const baseOs: Check = {
  id: 'base.os',
  section: 1,
  severity: 'high',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())
    const text = (await ctx.read('/etc/os-release')) ?? (await ctx.read('/usr/lib/os-release'))
    if (text === null) return skipped(ru.facts.notLinux())

    const release = parseOsRelease(text)
    const pretty =
      release.PRETTY_NAME ?? `${release.ID ?? '?'} ${release.VERSION_ID ?? ''}`.trim()
    const state = evaluateOsSupport(release, ctx.now)
    const findings = [ru.facts.distro(pretty)]

    if (!state.known) {
      findings.push(ru.facts.supportUnknown(state.key))
      return { status: 'unknown', findings, fix: 'base.os' }
    }

    if (state.status === 'fail') {
      findings.push(ru.facts.supportExpired(state.until ?? ''))
    } else if (state.status === 'warn') {
      findings.push(ru.facts.supportSoon(state.until ?? '', state.daysLeft ?? 0))
    } else {
      findings.push(ru.facts.supportUntil(state.until ?? '', state.daysLeft ?? 0))
    }
    return { status: state.status, findings, fix: 'base.os' }
  },
}
