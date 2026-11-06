import { ru } from '../../i18n/ru'
import {
  parseSystemdAnalyzeSecurity,
  unitFromCgroup,
  unitFromStatus,
} from '../../parsers/system'
import type { Ctx, Check } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'
import { loadSsListen } from '../net/ss-listen'

const SSH_UNIT_RE = /^ssh(?:d)?(?:\.|$)/i

/** Юнит процесса, который слушает порт: /proc/<pid>/cgroup, затем systemctl status */
async function resolveUnit(ctx: Ctx, pid: number): Promise<string | null> {
  const cgroup = await ctx.read(`/proc/${pid}/cgroup`)
  if (cgroup !== null) {
    const unit = unitFromCgroup(cgroup)
    if (unit !== null) return unit
  }
  const status = await ctx.run('systemctl', ['status', String(pid), '--no-pager'])
  return unitFromStatus(`${status.stdout}\n${status.stderr}`)
}

export const systemdSandbox: Check = {
  id: 'systemd.sandbox',
  section: 3,
  severity: 'medium',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    // Проверяем только службы, которые реально слушают порты. Общий разбор ss
    // с net.listen/net.firewall — второго вызова нет.
    const loaded = await loadSsListen(ctx)
    if (!loaded.ok) return unavailable('ss -ltnup', loaded.result)
    if (loaded.entries.length === 0) return skipped(ru.facts.noListeningServices())

    const pids = [...new Set(loaded.entries.map((entry) => entry.pid).filter((pid) => pid !== null))]
    if (pids.length === 0) {
      return { status: 'unknown', findings: [ru.facts.permissionDenied('ss -p')], fix: 'common.sudo' }
    }

    const units = new Set<string>()
    for (const pid of pids) {
      const unit = await resolveUnit(ctx, pid)
      if (unit !== null) units.add(unit)
    }
    if (units.size === 0) {
      return { status: 'unknown', findings: [ru.facts.unitsUnknown()], fix: 'common.sudo' }
    }

    const findings: string[] = []
    const evaluated: string[] = []
    let sshSkipped = false
    for (const unit of units) {
      if (SSH_UNIT_RE.test(unit)) {
        if (!sshSkipped) findings.push(ru.facts.sshNotEvaluated())
        sshSkipped = true
      } else {
        evaluated.push(unit)
      }
    }
    if (evaluated.length === 0) {
      return { status: 'ok', findings, fix: 'systemd.sandbox' }
    }

    const result = await ctx.run('systemd-analyze', ['security', '--no-pager', ...evaluated])
    if (!result.ok) {
      if (result.reason === 'missing') return skipped(ru.facts.commandMissing('systemd-analyze'))
      return unavailable('systemd-analyze security', result)
    }

    const wanted = new Set(evaluated)
    const exposures = parseSystemdAnalyzeSecurity(result.stdout)
      .filter((item) => wanted.has(item.unit) && Number(item.score) > 7)
      .sort((a, b) => Number(b.score) - Number(a.score))
    findings.push(...exposures.map((item) => ru.facts.serviceExposure(item.unit, item.score)))
    if (exposures.length === 0) findings.push(ru.facts.noConfig())
    return { status: exposures.length === 0 ? 'ok' : 'warn', findings, fix: 'systemd.sandbox' }
  },
}
