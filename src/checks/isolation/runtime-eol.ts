import {
  BUN_SUPPORT,
  NODE_SUPPORT,
  PHP_SUPPORT,
  POSTGRES_SUPPORT,
  PYTHON_SUPPORT,
  type RuntimeTable,
} from '../../data/runtimes'
import { ru } from '../../i18n/ru'
import { evaluateEol, parseVersion, runtimeKey } from '../../parsers/os'
import type { Check, Ctx, ExecResult, Status } from '../../types'
import { skipped, worstStatus } from '../shared'

interface RuntimeProbe {
  name: string
  command: string
  args: string[]
  table: RuntimeTable
  precision: 'major' | 'minor'
}

const PROBES: RuntimeProbe[] = [
  { name: 'node', command: 'node', args: ['--version'], table: NODE_SUPPORT, precision: 'major' },
  { name: 'bun', command: 'bun', args: ['--version'], table: BUN_SUPPORT, precision: 'minor' },
  { name: 'php', command: 'php', args: ['-v'], table: PHP_SUPPORT, precision: 'minor' },
  {
    name: 'python3',
    command: 'python3',
    args: ['--version'],
    table: PYTHON_SUPPORT,
    precision: 'minor',
  },
  {
    name: 'postgresql',
    command: 'psql',
    args: ['--version'],
    table: POSTGRES_SUPPORT,
    precision: 'minor',
  },
]

interface ProbeResult {
  findings: string[]
  statuses: Status[]
  found: boolean
}

function runProbe(
  probe: RuntimeProbe,
  result: ExecResult,
  now: Date,
): ProbeResult {
  const findings: string[] = []
  const statuses: Status[] = []
  if (!result.ok) {
    if (result.reason === 'missing') {
      findings.push(ru.facts.runtimeAbsent(probe.name))
    } else if (result.reason === 'denied') {
      findings.push(ru.facts.permissionDenied(probe.command))
      statuses.push('unknown')
    } else {
      findings.push(ru.facts.commandFailed(probe.command, result.stderr.trim().slice(0, 120)))
    }
    return { findings, statuses, found: false }
  }

  const text = `${result.stdout}\n${result.stderr}`
  const version = parseVersion(text)
  if (version === null) {
    findings.push(ru.facts.runtimeUnknown(probe.name, text.trim().slice(0, 40)))
    statuses.push('warn')
    return { findings, statuses, found: true }
  }
  const display = `${version.major}.${version.minor}.${version.patch}`
  findings.push(ru.facts.runtimeVersion(probe.name, display))
  const key = runtimeKey(probe.table.versions, version, probe.precision)
  if (key === null) {
    findings.push(ru.facts.runtimeUnknown(probe.name, display))
    statuses.push('warn')
    return { findings, statuses, found: true }
  }
  const state = evaluateEol(probe.table.versions, key, now)
  if (state.status === 'fail') {
    findings.push(ru.facts.supportExpired(state.until ?? ''))
    statuses.push('fail')
  } else if (state.status === 'warn') {
    findings.push(ru.facts.runtimeEol(probe.name, display, state.until ?? ''))
    statuses.push('warn')
  } else if (state.status === 'unknown') {
    findings.push(ru.facts.runtimeUnknown(probe.name, display))
    statuses.push('warn')
  } else {
    statuses.push('ok')
  }
  return { findings, statuses, found: true }
}

export const runtimeEol: Check = {
  id: 'runtime.eol',
  section: 3,
  severity: 'medium',
  async run(ctx: Ctx) {
    const findings: string[] = []
    const statuses: Status[] = []
    let foundAny = false

    for (const probe of PROBES) {
      const result = await ctx.run(probe.command, probe.args)
      const probeResult = runProbe(probe, result, ctx.now)
      findings.push(...probeResult.findings)
      statuses.push(...probeResult.statuses)
      foundAny = foundAny || probeResult.found
    }

    if (!foundAny && statuses.length === 0) {
      return skipped(ru.facts.noConfig())
    }
    return { status: worstStatus(statuses), findings, fix: 'runtime.eol' }
  },
}
