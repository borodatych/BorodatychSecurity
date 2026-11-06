import { ru } from '../../i18n/ru'
import type { Check } from '../../types'

export const opsMonitor: Check = {
  id: 'ops.monitor',
  section: 6,
  severity: 'medium',
  run() {
    return Promise.resolve({
      status: 'unknown' as const,
      findings: [ru.facts.monitorOutside()],
      fix: 'ops.monitor',
    })
  },
}
