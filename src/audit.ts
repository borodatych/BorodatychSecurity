import { hostname } from 'node:os'
import { createCtx } from './exec'
import { buildCsp, collectResources } from './recipes/csp'
import { detectStack } from './recipes/detect'
import type { Stack } from './recipes/types'
import { checks as registry } from './registry'
import { buildJsonReport } from './report/json'
import { runChecks } from './run'
import type { Check, Ctx, JsonReport, TlsHandshakeFn } from './types'
import { webSession } from './web/session'
import { VERSION } from './version'

/** Проверки сервера: всё, кроме раздела 5 «Сайт снаружи» */
export function serverChecks(): Check[] {
  return registry.filter((check) => check.section !== 5)
}

/** Проверки сайта снаружи: только раздел 5 */
export function siteChecks(): Check[] {
  return registry.filter((check) => check.section === 5)
}

export interface AuditOptions {
  /** Домен для проверок раздела 5 */
  domain?: string
  /** Пути файлов-приманок для проверки ops.canary */
  canaryPaths?: string[]
  /** Имя хоста в отчёте; по умолчанию системное */
  host?: string
  /** Момент старта; по умолчанию текущий */
  now?: Date
  /** Запросы сайта снаружи; по умолчанию глобальный fetch */
  fetch?: typeof fetch
  /** Рукопожатие TLS; по умолчанию прямое соединение node:tls */
  tlsHandshake?: TlsHandshakeFn
}

/** Стеки и стартовый CSP главной страницы; ошибка сбора не роняет аудит */
async function collectSite(ctx: Ctx): Promise<{ stacks: Stack[]; csp: string | null }> {
  try {
    const session = webSession(ctx)
    if (session === null) return { stacks: [], csp: null }
    // Сессия кэширует главную: лишнего запроса не будет, если её уже читали
    const home = await session.get('/')
    if (home.error !== null || home.status === 0) return { stacks: [], csp: null }
    const stacks = detectStack(home.headers)
    const csp = buildCsp(collectResources(home.body, `${session.origin}/`))
    return { stacks, csp }
  } catch {
    return { stacks: [], csp: null }
  }
}

/** Общий запуск проверок для CLI и MCP: только чтение, упавшая проверка — unknown */
export async function audit(
  selected: readonly Check[],
  options: AuditOptions = {},
): Promise<JsonReport> {
  const ctx = createCtx({
    ...(options.domain === undefined ? {} : { domain: options.domain }),
    ...(options.canaryPaths === undefined ? {} : { canaryPaths: options.canaryPaths }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.tlsHandshake === undefined ? {} : { tlsHandshake: options.tlsHandshake }),
  })
  const results = await runChecks(ctx, selected)
  const hasSiteChecks = selected.some((check) => check.section === 5)
  const site =
    options.domain !== undefined && hasSiteChecks ? await collectSite(ctx) : undefined
  return buildJsonReport(
    VERSION,
    options.host ?? hostname(),
    ctx.now.toISOString(),
    results,
    site,
  )
}
