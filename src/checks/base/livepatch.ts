import { ru } from '../../i18n/ru'
import { parseOsRelease } from '../../parsers/os'
import { parseProStatus } from '../../parsers/system'
import type { Check } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

export const baseLivepatch: Check = {
  id: 'base.livepatch',
  section: 1,
  severity: 'low',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())
    const text = (await ctx.read('/etc/os-release')) ?? (await ctx.read('/usr/lib/os-release'))
    if (text === null) return skipped(ru.facts.notLinux())
    const release = parseOsRelease(text)
    if ((release.ID ?? '').toLowerCase() !== 'ubuntu') {
      return skipped(ru.facts.distro(release.PRETTY_NAME ?? release.ID ?? 'не Ubuntu'))
    }

    const result = await ctx.run('pro', ['status'])
    if (!result.ok) return unavailable('pro status', result)
    const state = parseProStatus(`${result.stdout}\n${result.stderr}`)
    const findings = [state.attached ? ru.facts.proAttached() : ru.facts.proAbsent()]
    if (state.livepatch) findings.push(ru.facts.livepatchOn())
    else findings.push(ru.facts.livepatchOff())

    if (!state.attached) return { status: 'warn', findings, fix: 'base.livepatch' }
    if (!state.livepatch) return { status: 'warn', findings, fix: 'base.livepatch' }
    return { status: 'ok', findings, fix: 'base.livepatch' }
  },
}
