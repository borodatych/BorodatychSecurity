import { ru } from '../../i18n/ru'
import { parseBackupConfig } from '../../parsers/system'
import type { Check } from '../../types'
import { isLinux, skipped } from '../shared'

const FILE_PATHS = ['/etc/crontab', '/etc/anacrontab']
const DIR_PATHS = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly']

export const opsBackup: Check = {
  id: 'ops.backup',
  section: 6,
  severity: 'high',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const chunks: string[] = []
    const timers = await ctx.run('systemctl', ['list-timers', '--all', '--no-pager'])
    if (timers.ok) chunks.push(timers.stdout)
    const crontab = await ctx.run('crontab', ['-l'])
    if (crontab.ok) chunks.push(crontab.stdout)
    for (const path of FILE_PATHS) {
      const text = await ctx.read(path)
      if (text !== null) chunks.push(text)
    }
    for (const dir of DIR_PATHS) {
      const entries = await ctx.readdir(dir)
      if (entries === null) continue
      for (const name of entries) {
        const text = await ctx.read(`${dir}/${name}`)
        if (text !== null) chunks.push(text)
      }
    }

    if (chunks.length === 0) {
      return { status: 'unknown', findings: [ru.facts.noConfig()], fix: 'common.sudo' }
    }

    const jobs = parseBackupConfig(chunks.join('\n'))
    if (jobs.length === 0) {
      return { status: 'warn', findings: [ru.facts.backupNone()], fix: 'ops.backup' }
    }

    const findings = jobs.map((job) => ru.facts.backupFound(job.command, job.remote))
    const remote = jobs.some((job) => job.remote)
    return { status: remote ? 'ok' : 'fail', findings, fix: 'ops.backup' }
  },
}
