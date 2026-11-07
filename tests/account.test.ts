import { afterEach, describe, expect, test } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ApiClient } from '../src/account/api'
import {
  DEFAULT_API,
  clearToken,
  configDir,
  readToken,
  tokenPath,
  writeToken,
  type PasswdEntry,
} from '../src/account/config'
import { AccessError, requireAccess } from '../src/account/require'
import { ru } from '../src/i18n/ru'

const tempDirs: string[] = []

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'bsec-account-'))
  tempDirs.push(dir)
  return dir
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function sequenceFetch(responses: Response[]): typeof fetch {
  let index = 0
  const impl = (): Promise<Response> => {
    const response = responses[Math.min(index, responses.length - 1)]
    index += 1
    if (response === undefined) return Promise.reject(new Error('нет заготовленного ответа'))
    return Promise.resolve(response)
  }
  return impl as unknown as typeof fetch
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true })
  }
})

describe('путь и хранение токена', () => {
  test('XDG_CONFIG_HOME и HOME', () => {
    expect(tokenPath({ env: { XDG_CONFIG_HOME: '/tmp/xdg' } })).toBe(
      '/tmp/xdg/borodatych-security/token',
    )
    expect(tokenPath({ env: { HOME: '/home/bob' } })).toBe(
      '/home/bob/.config/borodatych-security/token',
    )
  })

  test('под sudo — дом SUDO_USER, без sudo — свой', () => {
    const lookup = (name: string): PasswdEntry | null =>
      name === 'alice' ? { home: '/home/alice', uid: 1001, gid: 1001 } : null
    expect(
      tokenPath({ env: { SUDO_USER: 'alice', HOME: '/root' }, uid: 0, lookupUser: lookup }),
    ).toBe('/home/alice/.config/borodatych-security/token')
    expect(
      tokenPath({ env: { SUDO_USER: 'alice', HOME: '/home/bob' }, uid: 1000, lookupUser: lookup }),
    ).toBe('/home/bob/.config/borodatych-security/token')
  })

  test('запись атомарная: каталог 700, файл 600, чтение работает', () => {
    const root = tempDir()
    const env = { XDG_CONFIG_HOME: root }
    const path = writeToken('bsec_test', { env })
    expect(path).toBe(tokenPath({ env }))
    expect(readFileSync(path, 'utf8').trim()).toBe('bsec_test')
    expect(statSync(configDir({ env })).mode & 0o777).toBe(0o700)
    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(readToken({ env })).toBe('bsec_test')
  })

  test('порядок чтения: явный токен, BOROSEC_TOKEN, файл', () => {
    const root = tempDir()
    const env = { XDG_CONFIG_HOME: root }
    writeToken('bsec_file', { env })
    expect(readToken({ env })).toBe('bsec_file')
    expect(readToken({ env: { ...env, BOROSEC_TOKEN: 'bsec_env' } })).toBe('bsec_env')
    expect(
      readToken({ env: { ...env, BOROSEC_TOKEN: 'bsec_env' }, token: 'bsec_explicit' }),
    ).toBe('bsec_explicit')
    expect(readToken({ env, token: null })).toBeNull()
  })

  test('logout удаляет файл и не падает без него', () => {
    const root = tempDir()
    const env = { XDG_CONFIG_HOME: root }
    writeToken('bsec_test', { env })
    expect(clearToken({ env })).toBe(true)
    expect(readToken({ env })).toBeNull()
    expect(clearToken({ env })).toBe(false)
  })
})

describe('pollToken', () => {
  test('pending → slow_down → токен, пауза растёт на 5 секунд', async () => {
    const client = new ApiClient({
      baseUrl: 'https://api.test',
      fetch: sequenceFetch([
        jsonResponse({ error: 'authorization_pending' }, 428),
        jsonResponse({ error: 'slow_down' }, 429),
        jsonResponse({ token: 'bsec_x', user: { email: 'u@example.ru' } }),
      ]),
    })
    let clock = 0
    const sleeps: number[] = []
    const outcome = await client.pollToken({
      deviceCode: 'dev',
      interval: 5,
      expiresIn: 600,
      now: () => clock,
      sleep: (ms) => {
        sleeps.push(ms)
        clock += ms
        return Promise.resolve()
      },
    })
    expect(outcome).toEqual({
      status: 'token',
      token: 'bsec_x',
      user: { email: 'u@example.ru' },
    })
    expect(sleeps).toEqual([5000, 10000])
  })

  test('410 — код истёк', async () => {
    const client = new ApiClient({
      baseUrl: 'https://api.test',
      fetch: sequenceFetch([jsonResponse({ error: 'expired_token' }, 410)]),
    })
    expect(
      await client.pollToken({
        deviceCode: 'dev',
        interval: 5,
        expiresIn: 600,
        now: () => 0,
        sleep: () => Promise.resolve(),
      }),
    ).toEqual({ status: 'expired' })
  })

  test('403 — человек отклонил вход', async () => {
    const client = new ApiClient({
      baseUrl: 'https://api.test',
      fetch: sequenceFetch([jsonResponse({ error: 'access_denied' }, 403)]),
    })
    expect(
      await client.pollToken({
        deviceCode: 'dev',
        interval: 5,
        expiresIn: 600,
        now: () => 0,
        sleep: () => Promise.resolve(),
      }),
    ).toEqual({ status: 'denied' })
  })

  test('expiresIn исчерпан — прекращаем опрос', async () => {
    const client = new ApiClient({
      baseUrl: 'https://api.test',
      fetch: sequenceFetch([jsonResponse({ error: 'authorization_pending' }, 428)]),
    })
    let clock = 0
    const outcome = await client.pollToken({
      deviceCode: 'dev',
      interval: 5,
      expiresIn: 5,
      now: () => clock,
      sleep: (ms) => {
        clock += ms
        return Promise.resolve()
      },
    })
    expect(outcome).toEqual({ status: 'expired' })
  })
})

describe('requireAccess', () => {
  test('нет токена — просим войти', async () => {
    try {
      await requireAccess('example.ru', {
        token: null,
        env: {},
        fetch: sequenceFetch([jsonResponse({})]),
      })
      throw new Error('ожидали ошибку доступа')
    } catch (error) {
      expect(error).toBeInstanceOf(AccessError)
      expect((error as AccessError).kind).toBe('login')
      expect((error as Error).message).toBe(ru.account.loginRequired)
    }
  })

  test('401 — токен отозван', async () => {
    try {
      await requireAccess('example.ru', {
        token: 'bsec_x',
        fetch: sequenceFetch([jsonResponse({ error: 'invalid_token' }, 401)]),
      })
      throw new Error('ожидали ошибку доступа')
    } catch (error) {
      expect(error).toBeInstanceOf(AccessError)
      expect((error as AccessError).kind).toBe('unauthorized')
      expect((error as Error).message).toBe(ru.account.tokenInvalid)
    }
  })

  test('allowed=false — бесплатные домены кончились', async () => {
    try {
      await requireAccess('example.ru', {
        token: 'bsec_x',
        fetch: sequenceFetch([
          jsonResponse({
            allowed: false,
            via: null,
            freeLeft: 0,
            passUntil: null,
            domain: 'example.ru',
          }),
          // лимит берётся из настроек сайта, а не из пакета
          jsonResponse({
            email: 'me@example.ru',
            access: { freeLimit: 5, freeUsed: 5, freeLeft: 0, freeSites: [], passes: [] },
          }),
        ]),
      })
      throw new Error('ожидали ошибку доступа')
    } catch (error) {
      expect(error).toBeInstanceOf(AccessError)
      expect((error as AccessError).kind).toBe('denied')
      expect((error as Error).message).toContain('5 из 5')
      expect((error as Error).message).toContain(`${DEFAULT_API}/my/checks`)
    }
  })

  test('allowed=true — возвращаем доступ', async () => {
    const access = await requireAccess('example.ru', {
      token: 'bsec_x',
      fetch: sequenceFetch([
        jsonResponse({
          allowed: true,
          via: 'free',
          freeLeft: 2,
          passUntil: null,
          domain: 'example.ru',
        }),
      ]),
    })
    expect(access.allowed).toBe(true)
    expect(access.via).toBe('free')
    expect(access.freeLeft).toBe(2)
  })
})
