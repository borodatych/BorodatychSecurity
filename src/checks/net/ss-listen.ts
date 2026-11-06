import { parseSsListen, type ListenEntry } from '../../parsers/system'
import type { Ctx, ExecErr, ExecResult } from '../../types'

export type SsListenLoad =
  | { ok: true; entries: ListenEntry[]; result: ExecResult }
  | { ok: false; result: ExecErr }

const cache = new WeakMap<Ctx, Promise<SsListenLoad>>()

/**
 * Один разбор `ss -ltnup` на весь запуск: net.listen, net.firewall и
 * systemd.sandbox читают один и тот же результат для одного ctx.
 */
export function loadSsListen(ctx: Ctx): Promise<SsListenLoad> {
  const cached = cache.get(ctx)
  if (cached !== undefined) return cached
  const pending = ctx.run('ss', ['-ltnup']).then((result): SsListenLoad => {
    if (!result.ok) return { ok: false, result }
    return { ok: true, entries: parseSsListen(result.stdout), result }
  })
  cache.set(ctx, pending)
  return pending
}
