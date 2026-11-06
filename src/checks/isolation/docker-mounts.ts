import { ru } from '../../i18n/ru'
import type { Check } from '../../types'
import { dockerContainers } from '../shared'

const DANGEROUS = new Set(['/', '/etc', '/root', '/home'])

function dangerousMount(source: string): boolean {
  if (DANGEROUS.has(source)) return true
  return /^\/home\/[^/]+$/.test(source) || /^\/root\/[^/]+$/.test(source)
}

export const dockerMounts: Check = {
  id: 'docker.mounts',
  section: 3,
  severity: 'high',
  async run(ctx) {
    const loaded = await dockerContainers(ctx)
    if (!loaded.ok) return loaded.result

    const findings: string[] = []
    for (const container of loaded.containers) {
      for (const mount of container.mounts) {
        if (dangerousMount(mount.source)) {
          findings.push(ru.facts.containerMount(container.name, mount.source))
        }
      }
    }

    if (findings.length === 0) {
      return { status: 'ok', findings: [ru.facts.noContainers()], fix: 'docker.mounts' }
    }
    return { status: 'fail', findings, fix: 'docker.mounts' }
  },
}
