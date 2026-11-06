import { ADMIN_PORTS, ALLOWED_PUBLIC_PORTS, DATABASE_PORTS } from '../../data/ports'
import { ru } from '../../i18n/ru'
import { isWildcardAddress } from '../../parsers/system'
import type { Check, Status } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'
import { loadSsListen } from './ss-listen'

export const netListen: Check = {
  id: 'net.listen',
  section: 2,
  // база — high; открытая наружу база поднимает важность до critical
  severity: 'high',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())
    const loaded = await loadSsListen(ctx)
    if (!loaded.ok) return unavailable('ss -ltnup', loaded.result)

    const exposed = loaded.entries.filter(
      (entry) => isWildcardAddress(entry.address) && !ALLOWED_PUBLIC_PORTS.has(entry.port),
    )
    if (exposed.length === 0) {
      return { status: 'ok', findings: [ru.facts.noExposedPorts()], fix: 'net.listen' }
    }

    let status: Status = 'ok'
    let severity: 'high' | 'critical' = 'high'
    const findings = exposed.map((entry) => {
      if (DATABASE_PORTS.has(entry.port)) {
        status = 'fail'
        severity = 'critical'
      } else if (status !== 'fail') status = 'warn'
      const label = DATABASE_PORTS.get(entry.port) ?? ADMIN_PORTS.get(entry.port) ?? ''
      const base = ru.facts.listening(entry.address, entry.port, entry.process)
      return label.length > 0 ? `${base} (${label})` : base
    })
    return { status, findings, severity, fix: 'net.listen' }
  },
}
