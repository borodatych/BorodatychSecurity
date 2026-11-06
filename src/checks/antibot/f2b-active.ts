import { ru } from '../../i18n/ru'
import { parseFail2banStatus } from '../../parsers/system'
import type { Check } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

export const f2bActive: Check = {
  id: 'f2b.active',
  section: 4,
  severity: 'high',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())
    const result = await ctx.run('fail2ban-client', ['status'])
    if (!result.ok) {
      if (result.reason === 'missing') {
        return { status: 'fail', findings: [ru.facts.fail2banAbsent()], fix: 'f2b.active' }
      }
      return unavailable('fail2ban-client status', result)
    }

    const status = parseFail2banStatus(result.stdout)
    if (status.jails.length === 0) {
      return { status: 'fail', findings: [ru.facts.noJails()], fix: 'f2b.active' }
    }
    const findings = status.jails.map((jail) => ru.facts.jailPresent(jail))
    const hasSsh = status.jails.some((jail) => jail.toLowerCase() === 'sshd')
    if (!hasSsh) {
      findings.push(ru.facts.jailAbsent('sshd'))
      return { status: 'fail', findings, fix: 'f2b.active' }
    }
    return { status: 'ok', findings, fix: 'f2b.active' }
  },
}
