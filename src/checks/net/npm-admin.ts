import { ru } from '../../i18n/ru'
import { parseDockerPsPorts } from '../../parsers/docker'
import type { Check } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

export const netNpmAdmin: Check = {
  id: 'net.npm-admin',
  section: 2,
  severity: 'high',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const docker = await ctx.run('docker', ['ps', '--format', '{{.Names}}\t{{.Ports}}'])
    if (!docker.ok) {
      if (docker.reason === 'missing') return skipped(ru.facts.noDocker())
      return unavailable('docker ps', docker)
    }

    const findings: string[] = []
    for (const container of parseDockerPsPorts(docker.stdout)) {
      for (const port of container.ports) {
        if (port.hostPort === 81 && (port.hostIp === '0.0.0.0' || port.hostIp === '::')) {
          findings.push(
            ru.facts.containerPort(container.name, port.hostIp, port.hostPort, port.containerPort),
          )
        }
      }
    }

    if (findings.length === 0) {
      return {
        status: 'skip',
        findings: [ru.facts.npmNotFound()],
        fix: 'net.npm-admin',
      }
    }
    return { status: 'fail', findings, fix: 'net.npm-admin' }
  },
}
