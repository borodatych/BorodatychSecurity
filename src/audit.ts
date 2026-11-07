import { hostname } from 'node:os'
import { createCtx } from './exec'
import { checks as registry } from './registry'
import { buildJsonReport } from './report/json'
import { runChecks } from './run'
import type { Check, JsonReport, TlsHandshakeFn } from './types'
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
  /** Имя хоста в отчёте; по умолчанию системное */
  host?: string
  /** Момент старта; по умолчанию текущий */
  now?: Date
  /** Запросы сайта снаружи; по умолчанию глобальный fetch */
  fetch?: typeof fetch
  /** Рукопожатие TLS; по умолчанию прямое соединение node:tls */
  tlsHandshake?: TlsHandshakeFn
}

/** Общий запуск проверок для CLI и MCP: только чтение, упавшая проверка — unknown */
export async function audit(
  selected: readonly Check[],
  options: AuditOptions = {},
): Promise<JsonReport> {
  const ctx = createCtx({
    ...(options.domain === undefined ? {} : { domain: options.domain }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.tlsHandshake === undefined ? {} : { tlsHandshake: options.tlsHandshake }),
  })
  const results = await runChecks(ctx, selected)
  return buildJsonReport(VERSION, options.host ?? hostname(), ctx.now.toISOString(), results)
}
