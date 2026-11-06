import { ru } from '../../i18n/ru'
import type { Check, Status } from '../../types'
import { dockerContainers, worstStatus } from '../shared'

const KNOWN_SOCK_USERS = /traefik|watchtower/i

export const dockerSock: Check = {
  id: 'docker.sock',
  section: 3,
  severity: 'critical',
  async run(ctx) {
    const loaded = await dockerContainers(ctx)
    if (!loaded.ok) return loaded.result

    const findings: string[] = []
    const statuses: Status[] = []
    for (const container of loaded.containers) {
      const usesSock = container.mounts.some(
        (mount) =>
          mount.source === '/var/run/docker.sock' ||
          mount.destination === '/var/run/docker.sock',
      )
      if (!usesSock) continue
      const known = KNOWN_SOCK_USERS.test(container.name) || KNOWN_SOCK_USERS.test(container.image)
      findings.push(ru.facts.containerSock(container.name, known))
      statuses.push(known ? 'warn' : 'fail')
    }

    if (findings.length === 0) {
      return { status: 'ok', findings: [ru.facts.noContainers()], fix: 'docker.sock' }
    }
    return { status: worstStatus(statuses), findings, fix: 'docker.sock' }
  },
}
