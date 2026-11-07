import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { webBanner } from '../src/checks/web/banner'
import { webCookies } from '../src/checks/web/cookies'
import { webCors } from '../src/checks/web/cors'
import { webHeaders } from '../src/checks/web/headers'
import { webRatelimit } from '../src/checks/web/ratelimit'
import { webSecrets } from '../src/checks/web/secrets'
import { webSourcemaps } from '../src/checks/web/sourcemaps'
import { webTls } from '../src/checks/web/tls'
import {
  auditCertificate,
  auditCookies,
  auditCors,
  auditRateLimit,
  auditSecurityHeaders,
  extractScriptSources,
  extractSourceMapUrls,
  findSecretLeaks,
  findVersionBanners,
  isSpaFallback,
  looksLikeSourceMap,
  parseSetCookie,
  type WebResponseData,
} from '../src/parsers/web'
import type { Ctx } from '../src/types'

function fixture(name: string): Record<string, unknown> {
  const path = join(import.meta.dir, 'fixtures', name)
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
}

const web = fixture('web.json')
const text = (key: string): string => {
  const value = web[key]
  return typeof value === 'string' ? value : ''
}
const headers = (key: string): Record<string, string> =>
  (web[key] ?? {}) as Record<string, string>
const list = (key: string): string[] => (web[key] ?? []) as string[]

const NOW = new Date('2026-11-06T12:00:00Z')
const MISSING: WebResponseData = {
  path: '/.borodatych-security-missing',
  status: 404,
  body: text('notFound'),
  headers: {},
}

function probe(path: string, body: string, status = 200): WebResponseData {
  return { path, status, body, headers: {} }
}

describe('web.secrets: сигнатуры и SPA-заглушка', () => {
  test('настоящие секреты находятся', () => {
    const leaks = findSecretLeaks(
      [
        probe('/.env', text('secretEnv')),
        probe('/.git/config', text('secretGitConfig')),
        probe('/.git/HEAD', text('secretGitHead')),
        probe('/config.json', text('secretConfig')),
        probe('/backup.sql', text('secretBackup')),
        probe('/server-status', text('secretServerStatus')),
        probe('/phpinfo.php', text('secretPhpinfo')),
      ],
      MISSING,
    )
    expect(leaks.map((leak) => leak.path)).toEqual([
      '/.env',
      '/.git/config',
      '/.git/HEAD',
      '/config.json',
      '/backup.sql',
      '/server-status',
      '/phpinfo.php',
    ])
  })

  test('SPA отдаёт один и тот же index.html — это не утечка', () => {
    const spa: WebResponseData = {
      path: '/.borodatych-security-missing',
      status: 200,
      body: text('spa'),
      headers: {},
    }
    expect(isSpaFallback(probe('/.env', text('spa')), spa)).toBe(true)
    expect(findSecretLeaks([probe('/.env', text('spa'))], spa)).toEqual([])
    expect(findSecretLeaks([probe('/.env', text('html'))], spa)).toEqual([])
  })

  test('404 не считается утечкой даже с похожим телом', () => {
    expect(findSecretLeaks([probe('/.env', text('secretEnv'), 404)], MISSING)).toEqual([])
  })
})

describe('web.sourcemaps', () => {
  test('скрипты и sourceMappingURL', () => {
    const scripts = extractScriptSources(text('html'), 'https://example.ru/')
    expect(scripts).toEqual([
      'https://example.ru/assets/app.js',
      'https://cdn.example.net/vendor.js',
    ])
    expect(extractSourceMapUrls(text('js'), 'https://example.ru/assets/app.js')).toEqual([
      'https://example.ru/assets/app.js.map',
    ])
  })

  test('карта отличается от обычного ответа', () => {
    expect(looksLikeSourceMap(text('sourceMap'), 'application/json')).toBe(true)
    expect(looksLikeSourceMap(text('html'), 'text/html')).toBe(false)
    expect(looksLikeSourceMap(text('spa'), 'text/html')).toBe(false)
  })
})

describe('web.headers', () => {
  test('полный набор и пустой', () => {
    expect(auditSecurityHeaders(headers('secureHeaders'))).toEqual({
      hsts: true,
      nosniff: true,
      frame: true,
      referrer: true,
      csp: true,
      cspReportOnly: false,
    })
    expect(auditSecurityHeaders(headers('weakHeaders'))).toEqual({
      hsts: false,
      nosniff: false,
      frame: false,
      referrer: false,
      csp: false,
      cspReportOnly: false,
    })
  })

  test('CSP только Report-Only — отмечается отдельно, а не как отсутствующий', () => {
    const audit = auditSecurityHeaders({
      'content-security-policy-report-only': "default-src 'self'",
    })
    expect(audit.csp).toBe(false)
    expect(audit.cspReportOnly).toBe(true)
  })
})

describe('web.cors', () => {
  test('опасные комбинации', () => {
    const origin = 'https://borodatych-security.invalid'
    expect(auditCors(headers('corsDanger'), origin).risk).toBe('fail')
    expect(auditCors(headers('corsWildcardCredentials'), origin).risk).toBe('fail')
    expect(auditCors(headers('corsWildcard'), origin).risk).toBe('ok')
    expect(auditCors({}, origin).risk).toBe('ok')
  })
})

describe('web.cookies', () => {
  test('флаги сессионной cookie', () => {
    expect(parseSetCookie('sessionid=abc; Path=/')).toEqual({
      name: 'sessionid',
      secure: false,
      httpOnly: false,
      sameSite: null,
      session: true,
      missing: ['Secure', 'HttpOnly', 'SameSite'],
    })
    expect(auditCookies(list('setCookies'))).toEqual([])
    const bad = auditCookies(list('badCookies'))
    expect(bad.length).toBe(1)
    expect(bad[0]?.name).toBe('sessionid')
  })
})

describe('web.tls: срок сертификата', () => {
  test('14 дней — fail, 30 — warn, дальше — ok', () => {
    expect(auditCertificate(new Date('2026-11-16T12:00:00Z'), NOW)).toEqual({
      daysLeft: 10,
      status: 'fail',
    })
    expect(auditCertificate(new Date('2026-11-26T12:00:00Z'), NOW)).toEqual({
      daysLeft: 20,
      status: 'warn',
    })
    expect(auditCertificate(new Date('2027-02-14T12:00:00Z'), NOW)).toEqual({
      daysLeft: 100,
      status: 'ok',
    })
  })
})

describe('web.ratelimit и web.banner', () => {
  test('429 считаются', () => {
    expect(auditRateLimit([200, 429, 429])).toEqual({ total: 3, tooMany: 2 })
  })

  test('версии в заголовках', () => {
    const banners = findVersionBanners({
      server: 'nginx/1.18.0',
      'x-powered-by': 'PHP/7.4.3',
      'content-type': 'text/html',
    })
    expect(banners).toEqual([
      { header: 'server', value: 'nginx/1.18.0' },
      { header: 'x-powered-by', value: 'PHP/7.4.3' },
    ])
    expect(findVersionBanners({ server: 'cloudflare' })).toEqual([])
  })
})

describe('web.* без --domain', () => {
  test('все проверки раздела 5 дают skip', async () => {
    const ctx = { platform: 'linux' } as Ctx
    const all = [
      webSecrets,
      webSourcemaps,
      webHeaders,
      webTls,
      webCors,
      webCookies,
      webRatelimit,
      webBanner,
    ]
    for (const check of all) {
      const result = await check.run(ctx)
      expect(result.status).toBe('skip')
      expect(result.findings[0]).toContain('--domain')
    }
  })
})
