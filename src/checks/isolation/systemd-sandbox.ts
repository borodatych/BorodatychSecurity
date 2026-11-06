import { ru } from '../../i18n/ru'
import { parseSystemdAnalyzeSecurity } from '../../parsers/system'
import type { Check } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

export const systemdSandbox: Check = {
  id: 'systemd.sandbox',
  section: 3,
  severity: 'medium',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())
    const result = await ctx.run('systemd-analyze', ['security', '--no-pager'])
    if (!result.ok) {
      if (result.reason === 'missing') return skipped(ru.facts.commandMissing('systemd-analyze'))
      return unavailable('systemd-analyze security', result)
    }

    const exposures = parseSystemdAnalyzeSecurity(result.stdout)
      .filter((item) => Number(item.score) > 7)
      .sort((a, b) => Number(b.score) - Number(a.score))
    if (exposures.length === 0) {
      return { status: 'ok', findings: [ru.facts.noConfig()], fix: 'systemd.sandbox' }
    }
    const findings = exposures.map((item) => ru.facts.serviceExposure(item.unit, item.score))
    return { status: 'warn', findings, fix: 'systemd.sandbox' }
  },
}
