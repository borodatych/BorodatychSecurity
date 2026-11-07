import { ru } from '../i18n/ru'
import { ApiClient, ApiError, type AccessResult } from './api'
import {
  apiBase,
  readToken,
  type AccountEnvOptions,
} from './config'

export type AccessErrorKind =
  | 'login'
  | 'unauthorized'
  | 'denied'
  | 'rate_limited'
  | 'network'
  | 'server'

/** Ошибка доступа: текст сразу пригоден человеку и агенту */
export class AccessError extends Error {
  readonly kind: AccessErrorKind

  constructor(kind: AccessErrorKind, message: string) {
    super(message)
    this.name = 'AccessError'
    this.kind = kind
  }
}

export interface RequireAccessOptions extends AccountEnvOptions {
  fetch?: typeof fetch
  baseUrl?: string
  token?: string | null
  timeoutMs?: number
}

/** Проверить, можно ли чинить домен сейчас; ошибка — понятный текст без стека */
export async function requireAccess(
  domain: string,
  options: RequireAccessOptions = {},
): Promise<AccessResult> {
  const env = options.env ?? process.env
  const token = readToken(options)
  if (token === null) throw new AccessError('login', ru.account.loginRequired)

  const client = new ApiClient({
    baseUrl: options.baseUrl ?? apiBase(env),
    token,
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  })

  let access: AccessResult
  try {
    access = await client.access(domain)
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.kind === 'unauthorized') {
        throw new AccessError('unauthorized', ru.account.tokenInvalid)
      }
      if (error.kind === 'rate_limited') {
        throw new AccessError('rate_limited', ru.account.rateLimited(error.retryAfter))
      }
      if (error.kind === 'network') {
        throw new AccessError('network', ru.account.network(error.message))
      }
      throw new AccessError('server', ru.account.serverError(error.status))
    }
    throw error
  }

  if (!access.allowed) {
    // Лимит бесплатных доменов задаёт сайт в настройках: число берём из ответа, а не из пакета
    const limit = await client
      .me()
      .then((me) => me.access.freeLimit)
      .catch(() => null)
    throw new AccessError('denied', ru.account.noFreeSlots(limit, apiBase(env)))
  }
  return access
}
