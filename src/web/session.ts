import type { WebResponseData } from '../parsers/web'
import type { Ctx } from '../types'
import { VERSION } from '../version'

/** Таймаут одного запроса раздела 5 */
export const WEB_TIMEOUT_MS = 10_000
/** Жёсткий лимит запросов на весь раздел 5 */
export const MAX_WEB_REQUESTS = 60
export const USER_AGENT = `borodatych-security/${VERSION}`

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>

export interface WebResult extends WebResponseData {
  error: string | null
}

export interface RequestOptions {
  headers?: Record<string, string>
  cache?: boolean
}

const sessions = new WeakMap<Ctx, WebSession>()

function originFor(domain: string): string {
  try {
    const withScheme = /^https?:\/\//i.test(domain) ? domain : `https://${domain}`
    return new URL(withScheme).origin
  } catch {
    return ''
  }
}

export class WebSession {
  readonly origin: string
  private count = 0
  private readonly cache = new Map<string, WebResult>()
  private readonly fetchImpl: FetchLike

  constructor(domain: string, fetchImpl: FetchLike = (input, init) => fetch(input, init)) {
    this.origin = originFor(domain)
    this.fetchImpl = fetchImpl
  }

  get used(): number {
    return this.count
  }

  get remaining(): number {
    return Math.max(0, MAX_WEB_REQUESTS - this.count)
  }

  async request(method: string, path: string, options: RequestOptions = {}): Promise<WebResult> {
    const cacheable = options.cache !== false
    if (this.origin.length === 0) {
      return { path, status: 0, body: '', headers: {}, error: 'invalid domain' }
    }
    let url: URL
    try {
      url = new URL(path, this.origin)
    } catch {
      return { path, status: 0, body: '', headers: {}, error: 'invalid url' }
    }
    // Никаких переходов на чужие домены: только запросы к исходному origin.
    if (url.origin !== this.origin) {
      return { path, status: 0, body: '', headers: {}, error: 'foreign domain' }
    }

    const key = `${method} ${url.pathname}${url.search}`
    if (cacheable) {
      const cached = this.cache.get(key)
      if (cached !== undefined) return cached
    }
    if (this.count >= MAX_WEB_REQUESTS) {
      return { path, status: 0, body: '', headers: {}, error: 'request budget exhausted' }
    }
    this.count += 1

    let result: WebResult
    try {
      const response = await this.fetchImpl(url.toString(), {
        method,
        headers: { 'user-agent': USER_AGENT, ...options.headers },
        redirect: 'manual',
        signal: AbortSignal.timeout(WEB_TIMEOUT_MS),
      })
      const headers: Record<string, string> = {}
      response.headers.forEach((value, name) => {
        headers[name.toLowerCase()] = value
      })
      const body = (await response.text()).slice(0, 512 * 1024)
      const setCookie = response.headers.getSetCookie()
      result = {
        path: url.pathname,
        status: response.status,
        body,
        headers,
        ...(setCookie.length === 0 ? {} : { setCookie }),
        error: null,
      }
    } catch (error) {
      result = {
        path,
        status: 0,
        body: '',
        headers: {},
        error: error instanceof Error ? error.message : String(error),
      }
    }

    if (cacheable && result.error === null) this.cache.set(key, result)
    return result
  }

  get(path: string, options: RequestOptions = {}): Promise<WebResult> {
    return this.request('GET', path, options)
  }
}

/** Одна сессия на ctx: всего не больше 60 запросов на раздел 5 */
export function webSession(ctx: Ctx): WebSession | null {
  if (ctx.domain === undefined) return null
  const existing = sessions.get(ctx)
  if (existing !== undefined) return existing
  const session = new WebSession(ctx.domain)
  sessions.set(ctx, session)
  return session
}
