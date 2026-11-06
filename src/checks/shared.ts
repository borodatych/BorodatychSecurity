import { ru } from '../i18n/ru'
import { parseDockerInspect, type DockerContainer } from '../parsers/docker'
import type { CheckResult, Ctx, ExecErr, ExecResult, Status } from '../types'

export function isLinux(ctx: Ctx): boolean {
  return ctx.platform === 'linux'
}

export function skipped(finding: string): CheckResult {
  return { status: 'skip', findings: [finding], fix: 'common.none' }
}

export function unavailable(cmd: string, result: ExecErr): CheckResult {
  let finding: string
  if (result.reason === 'missing') finding = ru.facts.commandMissing(cmd)
  else if (result.reason === 'denied') finding = ru.facts.permissionDenied(cmd)
  else if (result.reason === 'timeout') finding = ru.facts.timedOut(cmd)
  else finding = ru.facts.commandFailed(cmd, result.stderr.trim().slice(0, 200))
  return { status: 'unknown', findings: [finding], fix: 'common.sudo' }
}

export function commandOutput(result: ExecResult): string {
  return `${result.stdout}\n${result.stderr}`.trim()
}

const STATUS_ORDER: Status[] = ['fail', 'warn', 'unknown', 'skip', 'ok']

/** Худший статус из набора: fail > warn > unknown > skip > ok */
export function worstStatus(statuses: readonly Status[]): Status {
  for (const status of STATUS_ORDER) {
    if (statuses.includes(status)) return status
  }
  return 'ok'
}

export type DockerLoad =
  | { ok: true; containers: DockerContainer[] }
  | { ok: false; result: CheckResult }

/** Запущенные контейнеры через docker inspect; нет Docker — skip, нет прав — unknown */
export async function dockerContainers(ctx: Ctx): Promise<DockerLoad> {
  const ps = await ctx.run('docker', ['ps', '--format', '{{.Names}}'])
  if (!ps.ok) {
    if (ps.reason === 'missing') return { ok: false, result: skipped(ru.facts.noDocker()) }
    return { ok: false, result: unavailable('docker ps', ps) }
  }
  const names = ps.stdout
    .split(/\r?\n/)
    .map((name) => name.trim())
    .filter((name) => name.length > 0)
  if (names.length === 0) {
    return { ok: false, result: skipped(ru.facts.noContainers()) }
  }
  const inspect = await ctx.run('docker', ['inspect', ...names])
  if (!inspect.ok) return { ok: false, result: unavailable('docker inspect', inspect) }
  return { ok: true, containers: parseDockerInspect(inspect.stdout) }
}
