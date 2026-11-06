import { ru } from '../../i18n/ru'
import { parseAutoUpgrades } from '../../parsers/system'
import type { Check } from '../../types'
import { isLinux, skipped } from '../shared'

export const baseAutoupdates: Check = {
  id: 'base.autoupdates',
  section: 1,
  severity: 'high',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const config = await ctx.read('/etc/apt/apt.conf.d/20auto-upgrades')
    const enabled = await ctx.run('systemctl', ['is-enabled', 'unattended-upgrades'])
    const active = await ctx.run('systemctl', ['is-active', 'unattended-upgrades'])
    const state = config === null ? null : parseAutoUpgrades(config)

    const serviceEnabled = enabled.ok && enabled.stdout.trim() === 'enabled'
    const serviceActive = active.ok && active.stdout.trim() === 'active'
    const unattended = (state?.unattended ?? false) || serviceEnabled

    const findings = [
      ru.facts.setting('unattended-upgrades', unattended ? 'enabled' : 'disabled'),
      ru.facts.setting('таймер', serviceActive ? 'active' : 'inactive'),
    ]
    if (state !== null) {
      findings.push(
        ru.facts.setting(
          'APT::Periodic::Update-Package-Lists',
          state.updateLists ? '1' : '0',
        ),
      )
    }

    if (state === null && !enabled.ok) {
      findings.push(ru.facts.commandMissing('systemctl'))
      return { status: 'unknown', findings, fix: 'common.sudo' }
    }
    if (!unattended) return { status: 'fail', findings, fix: 'base.autoupdates' }
    if (state !== null && !state.updateLists) {
      return { status: 'warn', findings, fix: 'base.autoupdates' }
    }
    return { status: 'ok', findings, fix: 'base.autoupdates' }
  },
}
