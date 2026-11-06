import { ru } from '../../i18n/ru'
import { daysBetween } from '../../parsers/os'
import { parseAptSimulateSecurity } from '../../parsers/system'
import type { Check, Status } from '../../types'
import { isLinux, skipped, worstStatus } from '../shared'

export const basePending: Check = {
  id: 'base.pending',
  section: 1,
  severity: 'medium',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const rebootAt = await ctx.statMtime('/var/run/reboot-required')
    const simulate = await ctx.run('apt-get', ['-s', 'upgrade'])
    const findings: string[] = []
    const statuses: Status[] = []

    if (rebootAt !== null) {
      const days = Math.max(0, daysBetween(rebootAt, ctx.now))
      if (days > 7) {
        findings.push(ru.facts.rebootRequired(days))
        statuses.push('fail' as const)
      } else {
        findings.push(ru.facts.rebootRequiredFresh(days))
        statuses.push('ok' as const)
      }
    } else {
      findings.push(ru.facts.absent('reboot-required'))
    }

    if (simulate.ok) {
      const count = parseAptSimulateSecurity(simulate.stdout)
      if (count > 0) {
        findings.push(ru.facts.securityUpdates(count))
        statuses.push('warn' as const)
      } else {
        findings.push(ru.facts.noSecurityUpdates())
        statuses.push('ok' as const)
      }
    } else {
      findings.push(
        simulate.reason === 'denied'
          ? ru.facts.permissionDenied('apt-get -s upgrade')
          : ru.facts.commandMissing('apt-get'),
      )
      statuses.push('unknown' as const)
    }

    return { status: worstStatus(statuses), findings, fix: 'base.pending' }
  },
}
