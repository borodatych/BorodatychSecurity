import { connect as nodeConnect } from 'node:tls'
import { ru } from '../../i18n/ru'
import { auditCertificate } from '../../parsers/web'
import type { Check, Ctx, Status } from '../../types'
import { WEB_TIMEOUT_MS } from '../../web/session'
import { skipped, worstStatus } from '../shared'
import { webSkip } from './shared'

interface Certificate {
  valid_to: string
}

interface Handshake {
  cert: Certificate | null
  error: string | null
}

type SecureVersion = 'TLSv1.3' | 'TLSv1.2' | 'TLSv1.1' | 'TLSv1'

interface TlsSocket {
  once(event: 'secureConnect' | 'timeout', listener: () => void): void
  once(event: 'error', listener: (error: Error) => void): void
  getPeerCertificate(): { valid_to?: string }
  end(): void
  destroy(): void
}

type ConnectFn = (options: Record<string, unknown>) => TlsSocket

// @types/bun переопределяет node:tls и ломает вывод типа connect в typescript-eslint;
// сам вызов остаётся типизированным через узкий структурный интерфейс.
const connect = nodeConnect as unknown as ConnectFn

function endpoint(domain: string): { host: string; port: number } | null {
  try {
    const url = new URL(/^https?:\/\//i.test(domain) ? domain : `https://${domain}`)
    const port = url.port.length > 0 ? Number(url.port) : 443
    return Number.isInteger(port) && port > 0 ? { host: url.hostname, port } : null
  } catch {
    return null
  }
}

function handshake(host: string, port: number, maxVersion?: SecureVersion): Promise<Handshake> {
  return new Promise((resolve) => {
    let settled = false
    const finish = (result: Handshake): void => {
      if (settled) return
      settled = true
      resolve(result)
    }
    try {
      const socket = connect({
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: WEB_TIMEOUT_MS,
        ...(maxVersion === undefined ? {} : { maxVersion }),
      })
      socket.once('secureConnect', () => {
        const cert = socket.getPeerCertificate()
        socket.end()
        finish({
          cert:
            cert.valid_to === undefined || cert.valid_to.length === 0
              ? null
              : { valid_to: cert.valid_to },
          error: null,
        })
      })
      socket.once('error', (error: Error) => {
        socket.destroy()
        finish({ cert: null, error: error.message })
      })
      socket.once('timeout', () => {
        socket.destroy()
        finish({ cert: null, error: 'timeout' })
      })
    } catch (error) {
      finish({ cert: null, error: error instanceof Error ? error.message : String(error) })
    }
  })
}

// Внешний сайт подставляет рукопожатие с проверкой адреса на момент соединения
async function runHandshake(
  ctx: Ctx,
  host: string,
  port: number,
  maxVersion?: SecureVersion,
): Promise<Handshake> {
  if (ctx.tlsHandshake === undefined) return handshake(host, port, maxVersion)
  const result = await ctx.tlsHandshake({
    host,
    port,
    ...(maxVersion === undefined ? {} : { maxVersion }),
  })
  return {
    cert: result.validTo === null ? null : { valid_to: result.validTo },
    error: result.error,
  }
}

export const webTls: Check = {
  id: 'web.tls',
  section: 5,
  severity: 'high',
  async run(ctx) {
    const skip = webSkip(ctx)
    if (skip !== null) return skip
    const target = endpoint(ctx.domain ?? '')
    if (target === null) return skipped(ru.facts.webNoDomain())

    const main = await runHandshake(ctx, target.host, target.port)
    if (main.error !== null || main.cert === null) {
      return {
        status: 'unknown',
        findings: [ru.facts.webTlsFailed(main.error ?? 'нет сертификата')],
        fix: 'common.network',
      }
    }

    const validTo = new Date(main.cert.valid_to)
    if (Number.isNaN(validTo.getTime())) {
      return {
        status: 'unknown',
        findings: [ru.facts.webTlsFailed('не удалось разобрать срок сертификата')],
        fix: 'common.network',
      }
    }

    const cert = auditCertificate(validTo, ctx.now)
    const findings: string[] = []
    if (cert.status === 'fail') {
      findings.push(
        cert.daysLeft < 0
          ? ru.facts.webCertExpired(-cert.daysLeft)
          : ru.facts.webCertSoon(cert.daysLeft),
      )
    } else if (cert.status === 'warn') {
      findings.push(ru.facts.webCertSoon(cert.daysLeft))
    } else {
      findings.push(ru.facts.webCertDays(cert.daysLeft))
    }

    // Отказ от TLS 1.1 — хорошо; успешное рукопожатие — дыра.
    const legacy = await runHandshake(ctx, target.host, target.port, 'TLSv1.1')
    const statuses: Status[] = [cert.status]
    if (legacy.error === null) {
      findings.push(ru.facts.webLegacyTlsAccepted())
      statuses.push('fail')
    } else {
      findings.push(ru.facts.webLegacyTlsRefused())
      statuses.push('ok')
    }

    return { status: worstStatus(statuses), findings, fix: 'web.tls' }
  },
}
