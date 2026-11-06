import { ALLOWED_PUBLIC_PORTS } from '../../data/ports'
import { ru } from '../../i18n/ru'
import { isWildcardAddress, parseIptablesPolicy, parseUfwStatus } from '../../parsers/system'
import type { Check, Status } from '../../types'
import { isLinux, skipped, unavailable, worstStatus } from '../shared'
import { loadSsListen } from './ss-listen'

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
    const nftDenied = !nft.ok && nft.reason === 'denied'
    if (nftDenied) {
      findings.push(ru.facts.permissionDenied('nft list ruleset'))
      statuses.push('unknown')
    }

    const iptables = await ctx.run('iptables', ['-S'])
    if (iptables.ok) {
      const state = parseIptablesPolicy(iptables.stdout)
      findings.push(ru.facts.iptablesRules(state.rules))
      for (const [chain, policy] of Object.entries(state.policies)) {
        findings.push(ru.facts.policy(chain, policy))
      }
      const inputPolicy = state.policies.INPUT ?? ''
      if (state.rules > 0 || inputPolicy === 'DROP' || inputPolicy === 'REJECT') {
        statuses.push('ok')
        return { status: worstStatus(statuses), findings, fix: 'net.firewall' }
      }
    } else if (iptables.reason === 'denied') {
      findings.push(ru.facts.permissionDenied('iptables -S'))
      return { status: 'unknown', findings, fix: 'common.sudo' }
    }

    // Сетевого экрана нет. Второй слой нужен, но fail — только если наружу
    // торчит что-то кроме 22/80/443. Разбор ss общий с net.listen.
    const loaded = await loadSsListen(ctx)
    if (!loaded.ok) return unavailable('ss -ltnup', loaded.result)
    const exposed = loaded.entries.filter(
      (entry) => isWildcardAddress(entry.address) && !ALLOWED_PUBLIC_PORTS.has(entry.port),
    )
    findings.push(ru.facts.noFirewall())
    if (exposed.length === 0) {
      findings.push(ru.facts.firewallOnlyAllowed())
      statuses.push('warn')
    } else {
      findings.push(...exposed.map((entry) => ru.facts.listening(entry.address, entry.port, entry.process)))
      statuses.push('fail')
    }
    if (nftDenied) statuses.push('unknown')
    return { status: worstStatus(statuses), findings, fix: 'net.firewall' }
  },
}
