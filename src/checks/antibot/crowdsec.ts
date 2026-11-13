import { ru } from '../../i18n/ru'
import { parseCscliBouncersJson, parseCscliCapiStatus } from '../../parsers/system'
import type { Check, Status } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

/**
 * Баунсер, не забиравший решения дольше этого, считается мёртвым
 * Живой баунсер ходит за решениями раз в десятки секунд, сутки тишины — уже не задержка сети
 */
export const BOUNCER_STALE_HOURS = 24

const HOUR_MS = 3_600_000

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

    const bouncersResult = await ctx.run('cscli', ['bouncers', 'list', '-o', 'json'])
    if (!bouncersResult.ok) return unavailable('cscli bouncers list -o json', bouncersResult)
    const bouncers = parseCscliBouncersJson(bouncersResult.stdout)

    const capiResult = await ctx.run('cscli', ['capi', 'status'])
    if (!capiResult.ok) return unavailable('cscli capi status', capiResult)
    const capi = parseCscliCapiStatus(`${capiResult.stdout}\n${capiResult.stderr}`)

    const findings: string[] = []
    const statuses: Status[] = []

    if (bouncers === null) {
      findings.push(ru.facts.bouncersUnparsed())
      statuses.push('unknown')
    } else if (bouncers.length === 0) {
      findings.push(ru.facts.bouncersNone())
      statuses.push('fail')
    } else {
      // Мёртвый баунсер в списке выглядит как защита, а решения CrowdSec до сетевого экрана не доходят
      const staleBefore = ctx.now.getTime() - BOUNCER_STALE_HOURS * HOUR_MS
      let alive = 0
      for (const bouncer of bouncers) {
        if (!bouncer.valid) findings.push(ru.facts.bouncerRevoked(bouncer.name))
        else if (bouncer.lastPull === null) findings.push(ru.facts.bouncerNeverPulled(bouncer.name))
        else if (bouncer.lastPull.getTime() < staleBefore) {
          findings.push(ru.facts.bouncerStale(bouncer.name, bouncer.lastPull.toISOString(), BOUNCER_STALE_HOURS))
        } else {
          alive += 1
          findings.push(ru.facts.bouncerAlive(bouncer.name, bouncer.lastPull.toISOString()))
        }
      }
      if (alive === 0) statuses.push('fail')
    }

    findings.push(capi === true ? ru.facts.capiOn() : ru.facts.capiOff())
    if (capi === false) statuses.push('fail')
    if (capi === null) statuses.push('unknown')

    const status = statuses.includes('fail') ? 'fail' : statuses.includes('unknown') ? 'unknown' : 'ok'
    // База — low; сломанный CrowdSec поднимает важность до high
    return {
      status,
      findings,
      severity: status === 'fail' ? 'high' : 'low',
      fix: 'crowdsec',
    }
  },
}
