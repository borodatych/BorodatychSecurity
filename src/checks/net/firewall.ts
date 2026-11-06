import { ru } from '../../i18n/ru'
import { parseIptablesPolicy, parseUfwStatus } from '../../parsers/system'
import type { Check, Status } from '../../types'
import { isLinux, skipped, unavailable, worstStatus } from '../shared'

export const netFirewall: Check = {
  id: 'net.firewall',
  section: 2,
  severity: 'medium',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())
    const findings: string[] = []
    const statuses: Status[] = []

    const ufw = await ctx.run('ufw', ['status'])
    const ufwMissing = !ufw.ok && ufw.reason === 'missing'
    if (ufw.ok) {
      const state = parseUfwStatus(ufw.stdout)
      if (state === 'active') {
        return { status: 'ok', findings: [ru.facts.ufwActive()], fix: 'net.firewall' }
      }
      if (state === 'inactive') {
        findings.push(ru.facts.ufwInactive())
      }
    } else if (!ufwMissing) {
      return unavailable('ufw status', ufw)
    }

    const nft = await ctx.run('nft', ['list', 'ruleset'])
    if (nft.ok && nft.stdout.trim().length > 0) {
      findings.push(ru.facts.nftRules())
      return { status: 'ok', findings, fix: 'net.firewall' }
    }
    const nftMissing = !nft.ok && nft.reason === 'missing'
    if (!nft.ok && nft.reason === 'denied') {
      findings.push(ru.facts.permissionDenied('nft list ruleset'))
      statuses.push('unknown')
    }

    const iptables = await ctx.run('iptables', ['-S'])
    const iptablesMissing = !iptables.ok && iptables.reason === 'missing'
    if (iptables.ok) {
      const state = parseIptablesPolicy(iptables.stdout)
      findings.push(ru.facts.iptablesRules(state.rules))
      for (const [chain, policy] of Object.entries(state.policies)) {
        findings.push(ru.facts.policy(chain, policy))
      }
      const inputPolicy = state.policies.INPUT ?? ''
      if (state.rules > 0 || inputPolicy === 'DROP' || inputPolicy === 'REJECT') {
        statuses.push('ok')
      } else {
        statuses.push('fail')
      }
      return { status: worstStatus(statuses), findings, fix: 'net.firewall' }
    }

    if (iptables.reason === 'denied') {
      findings.push(ru.facts.permissionDenied('iptables -S'))
      statuses.push('unknown')
      return { status: 'unknown', findings, fix: 'common.sudo' }
    }

    if (ufwMissing && nftMissing && iptablesMissing) {
      return { status: 'fail', findings: [ru.facts.noFirewall()], fix: 'net.firewall' }
    }
    return { status: 'unknown', findings, fix: 'common.sudo' }
  },
}
