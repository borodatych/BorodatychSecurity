import { ru } from '../../i18n/ru'
import type { Check, Status } from '../../types'
import { dockerContainers, worstStatus } from '../shared'

function isRoot(user: string): boolean {
  return user.length === 0 || user === 'root' || user === '0' || user.startsWith('0:')
}

export const dockerRoot: Check = {
  id: 'docker.root',
  section: 3,
  severity: 'high',
  async run(ctx) {
    const loaded = await dockerContainers(ctx)
    if (!loaded.ok) return loaded.result

    const findings: string[] = []
    const statuses: Status[] = []
    for (const container of loaded.containers) {
      if (container.privileged) {
        findings.push(ru.facts.containerPrivileged(container.name))
        statuses.push('fail')
      }
      if (isRoot(container.user)) {
        if (!container.capDrop.some((cap) => cap.toUpperCase() === 'ALL')) {
          findings.push(ru.facts.containerRoot(container.name))
          findings.push(ru.facts.containerNoCapDrop(container.name))
          statuses.push('warn')
        }
      }
      const noNewPrivileges = container.securityOpt.some((opt) =>
        /no-new-privileges/i.test(opt),
      )
      if (!noNewPrivileges) {
        findings.push(ru.facts.containerNoNewPrivileges(container.name))
        statuses.push('warn')
      }
    }

    if (findings.length === 0) {
      return { status: 'ok', findings: [ru.facts.noContainers()], fix: 'docker.root' }
    }
    return { status: worstStatus(statuses), findings, fix: 'docker.root' }
  },
}
