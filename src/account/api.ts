import { USER_AGENT } from '../web/session'
import { DEFAULT_API } from './config'

/** Таймаут одного запроса к сервису */
export const API_TIMEOUT_MS = 15_000

export type ApiErrorKind = 'unauthorized' | 'rate_limited' | 'network' | 'server'

/** Типизированная ошибка сервиса: вид, HTTP-статус и retryAfter для 429 */
export class ApiError extends Error {
  readonly kind: ApiErrorKind
  readonly status: number
  readonly retryAfter: number | null

  constructor(
    kind: ApiErrorKind,
    message: string,
    status = 0,
    retryAfter: number | null = null,
  ) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind
    this.status = status
    this.retryAfter = retryAfter
  }
}

export interface DeviceStart {
  deviceCode: string
  userCode: string
  verificationUrl: string
  expiresIn: number
  interval: number
}

export interface AuthUser {
  email: string
}

export interface TokenResult {
  token: string
  user: AuthUser
}

export interface AccessResult {
  allowed: boolean
  via: 'pass' | 'free' | null
  freeLeft: number
  passUntil: string | null
  domain: string
}

export interface FreeSite {
  domain: string
  createdAt: string
}

export interface PassInfo {
  domain: string
  until: string
}

export interface MeResult {
  email: string
  access: {
    freeLimit: number
    freeUsed: number
    freeLeft: number
    freeSites: FreeSite[]
    passes: PassInfo[]
  }
}

export interface ApiClientOptions {
  baseUrl?: string
  token?: string | null
  fetch?: typeof fetch
  timeoutMs?: number
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>

export type PollOutcome =
  | { status: 'token'; token: string; user: AuthUser }
  | { status: 'denied' }
  | { status: 'expired' }

export interface PollTokenOptions {
  deviceCode: string
  interval: number
  expiresIn: number
  /** Пауза между опросами; в тестах подменяется */
  sleep?: (ms: number) => Promise<void>
  /** Часы для контроля expiresIn; в тестах подменяются */
  now?: () => number
}

interface ErrorBody {
  error?: string
  retryAfter?: number
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  return value as Record<string, unknown>
}

async function errorBody(response: Response): Promise<ErrorBody> {
  try {
    const record = asRecord(await response.json())
    if (record === null) return {}
    const body: ErrorBody = {}
    if (typeof record.error === 'string') body.error = record.error
    if (typeof record.retryAfter === 'number') body.retryAfter = record.retryAfter
    return body
  } catch {
    return {}
  }
}

function asDeviceStart(value: unknown): DeviceStart {
  const record = asRecord(value)
  if (record === null) throw new ApiError('server', 'неожиданный ответ /device')
  const { deviceCode, userCode, verificationUrl, expiresIn, interval } = record
  if (
    typeof deviceCode !== 'string' ||
    typeof userCode !== 'string' ||
    typeof verificationUrl !== 'string' ||
    typeof expiresIn !== 'number' ||
    typeof interval !== 'number'
  ) {
    throw new ApiError('server', 'неожиданный ответ /device')
  }
  return { deviceCode, userCode, verificationUrl, expiresIn, interval }
}

function asTokenResult(value: unknown): TokenResult {
  const record = asRecord(value)
  const user = record === null ? null : asRecord(record.user)
  if (
    record === null ||
    typeof record.token !== 'string' ||
    user === null ||
    typeof user.email !== 'string'
  ) {
    throw new ApiError('server', 'неожиданный ответ /token')
  }
  return { token: record.token, user: { email: user.email } }
}

function asAccess(value: unknown): AccessResult {
  const record = asRecord(value)
  if (record === null || typeof record.allowed !== 'boolean') {
    throw new ApiError('server', 'неожиданный ответ /access')
  }
  const via = record.via
  const freeLeft = record.freeLeft
  const passUntil = record.passUntil
  const domain = record.domain
  if (
    (via !== 'pass' && via !== 'free' && via !== null) ||
    typeof freeLeft !== 'number' ||
    (passUntil !== null && typeof passUntil !== 'string') ||
    typeof domain !== 'string'
  ) {
    throw new ApiError('server', 'неожиданный ответ /access')
  }
  return { allowed: record.allowed, via, freeLeft, passUntil, domain }
}

function asMe(value: unknown): MeResult {
  const record = asRecord(value)
  const access = record === null ? null : asRecord(record.access)
  if (record === null || typeof record.email !== 'string' || access === null) {
    throw new ApiError('server', 'неожиданный ответ /me')
  }
  const { freeLimit, freeUsed, freeLeft, freeSites, passes } = access
  if (
    typeof freeLimit !== 'number' ||
    typeof freeUsed !== 'number' ||
    typeof freeLeft !== 'number' ||
    !Array.isArray(freeSites) ||
    !Array.isArray(passes)
  ) {
    throw new ApiError('server', 'неожиданный ответ /me')
  }
  return {
    email: record.email,
    access: {
      freeLimit,
      freeUsed,
      freeLeft,
      freeSites: freeSites.flatMap((item) => {
        const site = asRecord(item)
        return site !== null &&
          typeof site.domain === 'string' &&
          typeof site.createdAt === 'string'
          ? [{ domain: site.domain, createdAt: site.createdAt }]
          : []
      }),
      passes: passes.flatMap((item) => {
        const pass = asRecord(item)
        return pass !== null && typeof pass.domain === 'string' && typeof pass.until === 'string'
          ? [{ domain: pass.domain, until: pass.until }]
          : []
      }),
    },
  }
}

/** Клиент API входа и проверки доступа; fetch подменяется в тестах */
export class ApiClient {
  readonly baseUrl: string
  private readonly token: string | null
  private readonly fetchImpl: FetchLike
  private readonly timeoutMs: number

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_API).replace(/\/+$/, '')
    this.token = options.token ?? null
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init))
    this.timeoutMs = options.timeoutMs ?? API_TIMEOUT_MS
  }

  private async send(path: string, init: RequestInit = {}): Promise<Response> {
    const headers: Record<string, string> = {
      'user-agent': USER_AGENT,
      accept: 'application/json',
    }
    if (init.body !== undefined) headers['content-type'] = 'application/json'
    if (this.token !== null) headers.authorization = `Bearer ${this.token}`
    try {
      return await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        headers,
        signal: AbortSignal.timeout(this.timeoutMs),
      })
    } catch (error) {
      throw new ApiError('network', error instanceof Error ? error.message : String(error))
    }
  }

  private async failure(response: Response): Promise<ApiError> {
    const body = await errorBody(response)
    if (response.status === 401) {
      return new ApiError('unauthorized', 'токен неверен или отозван', 401)
    }
    if (response.status === 429) {
      return new ApiError('rate_limited', 'слишком много запросов', 429, body.retryAfter ?? null)
    }
    return new ApiError('server', `HTTP ${String(response.status)}`, response.status)
  }

  async startDevice(name: string): Promise<DeviceStart> {
    const response = await this.send('/api/cli/v1/device', {
      method: 'POST',
      body: JSON.stringify({ clientName: name }),
    })
    if (response.status !== 200) throw await this.failure(response)
    return asDeviceStart(await response.json())
  }

  /** Опрос кода устройства: pending и slow_down ждут, 403 и 410 прекращают опрос */
  async pollToken(options: PollTokenOptions): Promise<PollOutcome> {
    const sleep = options.sleep ?? defaultSleep
    const now = options.now ?? Date.now
    const deadline = now() + options.expiresIn * 1000
    let wait = Math.max(options.interval, 1) * 1000

    for (;;) {
      if (now() >= deadline) return { status: 'expired' }
      const response = await this.send('/api/cli/v1/token', {
        method: 'POST',
        body: JSON.stringify({ deviceCode: options.deviceCode }),
      })
      if (response.status === 200) {
        const result = asTokenResult(await response.json())
        return { status: 'token', token: result.token, user: result.user }
      }

      if (response.status === 403) return { status: 'denied' }
      if (response.status === 410) return { status: 'expired' }
      if (response.status === 429) {
        // Сервер просит реже: добавляем 5 секунд к паузе
        wait += 5000
      } else if (response.status !== 428) {
        throw await this.failure(response)
      }

      const remaining = deadline - now()
      if (remaining <= 0) return { status: 'expired' }
      await sleep(Math.min(wait, remaining))
    }
  }

  async access(domain: string): Promise<AccessResult> {
    const response = await this.send(
      `/api/cli/v1/access?domain=${encodeURIComponent(domain)}`,
      { method: 'GET' },
    )
    if (response.status !== 200) throw await this.failure(response)
    return asAccess(await response.json())
  }

  async me(): Promise<MeResult> {
    const response = await this.send('/api/cli/v1/me', { method: 'GET' })
    if (response.status !== 200) throw await this.failure(response)
    return asMe(await response.json())
  }
}
