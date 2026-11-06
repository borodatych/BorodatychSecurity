import { ru } from '../../i18n/ru'
import { parseFail2banChain } from '../../parsers/system'
import type { Check } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

const CONFIG_PATHS = ['/etc/fail2ban/jail.local', '/etc/fail2ban/jail.conf']
const CONFIG_DIRS = ['/etc/fail2ban/jail.d']

export const f2bDocker: Check = {
  id: 'f2b.docker',
  section: 4,
  severity: 'high',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const docker = await ctx.run('docker', ['ps', '--format', '{{.Names}}'])
    if (!docker.ok) {
      if (docker.reason === 'missing') return skipped(ru.facts.noDocker())
      return unavailable('docker ps', docker)
    }

    const f2b = await ctx.run('fail2ban-client', ['status'])
    if (!f2b.ok) {
      if (f2b.reason === 'missing') return skipped(ru.facts.fail2banAbsent())
      return unavailable('fail2ban-client status', f2b)
    }

    const parts: string[] = []
    for (const path of CONFIG_PATHS) {
      const text = await ctx.read(path)
      if (text !== null) parts.push(text)
    }
    for (const dir of CONFIG_DIRS) {
      const entries = await ctx.readdir(dir)
      if (entries === null) continue
      for (const name of entries) {
        if (!name.endsWith('.conf') && !name.endsWith('.local')) continue
        const text = await ctx.read(`${dir}/${name}`)
        if (text !== null) parts.push(text)
      }
    }
    if (parts.length === 0) {
      return { status: 'unknown', findings: [ru.facts.noConfig()], fix: 'common.sudo' }
    }

    const chain = parseFail2banChain(parts.join('\n'))
    const findings: string[] = []
    if (chain.chain !== null) findings.push(ru.facts.f2bChain(chain.chain))
    if (chain.banaction !== null) findings.push(ru.facts.f2bBanaction(chain.banaction))

    if (chain.chain !== null && chain.chain.toUpperCase() === 'DOCKER-USER') {
      return { status: 'ok', findings, fix: 'f2b.docker' }
    }
    if (chain.banaction !== null) {
      return { status: 'fail', findings, fix: 'f2b.docker' }
    }
    return { status: 'unknown', findings, fix: 'f2b.docker' }
  },
}
