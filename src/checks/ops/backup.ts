import { ru } from '../../i18n/ru'
import {
  classifyBackupCommand,
  isBackupText,
  parseExecStart,
  parseSystemdTimers,
  parseTimerUnit,
  redactSecrets,
} from '../../parsers/system'
import type { Ctx, Check, Status } from '../../types'
import { isLinux, skipped, worstStatus } from '../shared'

const FILE_PATHS = ['/etc/crontab', '/etc/anacrontab']
const DIR_PATHS = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly']

interface Candidate {
  source: string
  command: string
}

function cronCandidates(text: string, source: string): Candidate[] {
  const result: Candidate[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line.length === 0 || line.startsWith('#')) continue
    if (!isBackupText(line)) continue
    result.push({ source, command: line })
  }
  return result
}

/** Таймеры systemd: имя таймера/юнита или ExecStart похожи на бэкап */
async function timerCandidates(ctx: Ctx): Promise<{ candidates: Candidate[]; available: boolean }> {
  const timersResult = await ctx.run('systemctl', ['list-timers', '--all', '--no-pager'])
  if (!timersResult.ok) return { candidates: [], available: false }

  const candidates: Candidate[] = []
  for (const timer of parseSystemdTimers(timersResult.stdout)) {
    let activation = timer.activates[0]
    if (activation === undefined) {
      const timerUnit = await ctx.run('systemctl', ['cat', timer.unit])
      if (timerUnit.ok) {
        const parsed = parseTimerUnit(timerUnit.stdout)
        if (parsed !== null) activation = parsed
      }
    }

    let commands: string[] = []
    if (activation !== undefined) {
      const service = await ctx.run('systemctl', ['cat', activation])
      if (service.ok) commands = parseExecStart(service.stdout)
    }

    const named = isBackupText(timer.unit) || isBackupText(activation ?? '')
    if (commands.length === 0 && named) {
      candidates.push({ source: timer.unit, command: activation ?? timer.unit })
    }
    for (const command of commands) {
      if (named || isBackupText(command)) candidates.push({ source: timer.unit, command })
    }
  }
  return { candidates, available: true }
}

export const opsBackup: Check = {
  id: 'ops.backup',
  section: 6,
  severity: 'high',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const candidates: Candidate[] = []
    let cronAvailable = false
    const crontab = await ctx.run('crontab', ['-l'])
    if (crontab.ok) {
      cronAvailable = true
      candidates.push(...cronCandidates(crontab.stdout, 'crontab'))
    }
    for (const path of FILE_PATHS) {
      const text = await ctx.read(path)
      if (text === null) continue
      cronAvailable = true
      candidates.push(...cronCandidates(text, path))
    }
    for (const dir of DIR_PATHS) {
      const entries = await ctx.readdir(dir)
      if (entries === null) continue
      cronAvailable = true
      for (const name of entries) {
        const text = await ctx.read(`${dir}/${name}`)
        if (text !== null) candidates.push(...cronCandidates(text, `${dir}/${name}`))
      }
    }

    const timers = await timerCandidates(ctx)
    candidates.push(...timers.candidates)

    if (!cronAvailable && !timers.available) {
      return { status: 'unknown', findings: [ru.facts.noConfig()], fix: 'common.sudo' }
    }
    if (candidates.length === 0) {
      return { status: 'warn', findings: [ru.facts.backupNone()], fix: 'ops.backup' }
    }

    const findings: string[] = []
    const statuses: Status[] = []
    const seen = new Set<string>()
    for (const candidate of candidates) {
      const command = redactSecrets(candidate.command).slice(0, 200)
      if (seen.has(command)) continue
      seen.add(command)
      const target = classifyBackupCommand(candidate.command)
      if (target === 'remote') {
        findings.push(ru.facts.backupRemote(candidate.source, command))
        statuses.push('ok')
      } else if (target === 'local') {
        findings.push(ru.facts.backupLocal(candidate.source, command))
        statuses.push('fail')
      } else {
        findings.push(ru.facts.backupUnknown(candidate.source, command))
        statuses.push('warn')
      }
    }

    return { status: worstStatus(statuses), findings, fix: 'ops.backup' }
  },
}
