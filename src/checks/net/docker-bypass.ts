import { ru } from '../../i18n/ru'
import { parseDockerPsPorts } from '../../parsers/docker'
import { parseUfwStatus } from '../../parsers/system'
import type { Check } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

export const netDockerBypass: Check = {
  id: 'net.docker-bypass',
  section: 2,
  severity: 'critical',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const docker = await ctx.run('docker', ['ps', '--format', '{{.Names}}\t{{.Ports}}'])
    if (!docker.ok) {
      if (docker.reason === 'missing') return skipped(ru.facts.noDocker())
      return unavailable('docker ps', docker)
    }
    const containers = parseDockerPsPorts(docker.stdout).filter((entry) => entry.ports.length > 0)
    if (containers.length === 0) return skipped(ru.facts.noContainers())

    const ufw = await ctx.run('ufw', ['status'])
    if (!ufw.ok) {
      if (ufw.reason === 'missing') return skipped(ru.facts.noFirewall())
      return unavailable('ufw status', ufw)
    }
    const state = parseUfwStatus(ufw.stdout)
    if (state !== 'active') return skipped(ru.facts.ufwInactive())

    const findings: string[] = [ru.facts.ufwActive()]
    let bypass = false
    for (const container of containers) {
      for (const port of container.ports) {
        if (port.hostIp === '0.0.0.0' || port.hostIp === '::' || port.hostIp === '*') {
          bypass = true
          findings.push(
            ru.facts.containerPort(container.name, port.hostIp, port.hostPort, port.containerPort),
          )
        }
      }
    }

    return {
      status: bypass ? 'fail' : 'ok',
      findings: bypass ? findings : [ru.facts.ufwActive()],
      fix: 'net.docker-bypass',
    }
  },
}
