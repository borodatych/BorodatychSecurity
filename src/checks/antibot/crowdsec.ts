import { ru } from '../../i18n/ru'
import { parseCscliBouncers, parseCscliCapiStatus } from '../../parsers/system'
import type { Check, Status } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

export const crowdsec: Check = {
  id: 'crowdsec',
  section: 4,
  severity: 'low',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const version = await ctx.run('cscli', ['version'])
    if (!version.ok) {
      if (version.reason === 'missing') {
        return { status: 'warn', findings: [ru.facts.cscliAbsent()], fix: 'crowdsec' }
      }
      return unavailable('cscli version', version)
    }

    const bouncersResult = await ctx.run('cscli', ['bouncers', 'list'])
    if (!bouncersResult.ok) return unavailable('cscli bouncers list', bouncersResult)
    const bouncers = parseCscliBouncers(bouncersResult.stdout)

    const capiResult = await ctx.run('cscli', ['capi', 'status'])
    if (!capiResult.ok) return unavailable('cscli capi status', capiResult)
    const capi = parseCscliCapiStatus(`${capiResult.stdout}\n${capiResult.stderr}`)

    const findings = [
      bouncers.length === 0 ? ru.facts.bouncersNone() : ru.facts.bouncerCount(bouncers.length),
      capi === true ? ru.facts.capiOn() : ru.facts.capiOff(),
    ]

    const statuses: Status[] = []
    if (bouncers.length === 0) statuses.push('fail')
    if (capi === false) statuses.push('fail')
    if (capi === null) statuses.push('unknown')
    if (statuses.length === 0) statuses.push('ok')

    const status = statuses.includes('fail') ? 'fail' : statuses.includes('unknown') ? 'unknown' : 'ok'
    return { status, findings, fix: 'crowdsec' }
  },
}
