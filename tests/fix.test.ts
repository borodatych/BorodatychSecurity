import { describe, expect, test } from 'bun:test'
import { AccessError } from '../src/account/require'
import { planCaddyFix, caddySnippetFile, parseCaddyfile } from '../src/fix/caddy'
import { diffLines, unifiedDiff } from '../src/fix/diff'
import {
  NGINX_HEADERS_INCLUDE,
  NGINX_HEADERS_SNIPPET_PATH,
  NGINX_INCLUDE,
  NGINX_SNIPPET_PATH,
  planNginxFix,
  parseNginxDump,
  serversForDomain,
  matchesDomain,
  httpIncludesConfD,
} from '../src/fix/nginx'
import { runFix, AUTO_FIX_CHECKS } from '../src/fix/run'
import type { FixArgs } from '../src/fix/args'
import type { FixCtx, FileInfo } from '../src/fix/types'
import type { Check, ExecResult, JsonReport, Status } from '../src/types'

const CSP = "default-src 'self'; object-src 'none'; frame-ancestors 'self'"
const NGINX_CONF = '/etc/nginx/nginx.conf'
const SITE_CONF = '/etc/nginx/conf.d/example.ru.conf'
const CADDYFILE = '/etc/caddy/Caddyfile'

function ok(stdout = ''): ExecResult {
  return { ok: true, stdout, stderr: '', code: 0 }
}

function bad(stderr = '', reason: 'missing' | 'denied' | 'timeout' | 'error' = 'error'): ExecResult {
  return { ok: false, reason, stdout: '', stderr, code: 1 }
}

class FakeCtx implements FixCtx {
  platform: NodeJS.Platform = 'linux'
  uid: number | null = 0
  now = new Date('2026-11-07T12:00:00.000Z')
  files = new Map<string, string>()
  modes = new Map<string, number>()
  owners = new Map<string, { uid: number; gid: number }>()
  dirs: { path: string; mode: number }[] = []
  commands: { cmd: string; args: readonly string[] }[] = []
  writes: string[] = []
  removed: string[] = []
  outText: string[] = []
  errText: string[] = []
  confirmQuestions: string[] = []
  confirmAnswer = true
  stdinIsTTY = true
  sleeps: number[] = []
  handler: (cmd: string, args: readonly string[]) => ExecResult

  constructor(handler?: (cmd: string, args: readonly string[]) => ExecResult) {
    this.handler = handler ?? (() => ok())
  }

  run = (cmd: string, args: readonly string[] = []): Promise<ExecResult> => {
    this.commands.push({ cmd, args })
    return Promise.resolve(this.handler(cmd, args))
  }

  read = (path: string): Promise<string | null> =>
    Promise.resolve(this.files.get(path) ?? null)

  write = (path: string, content: string): Promise<void> => {
    this.writes.push(path)
    this.files.set(path, content)
    if (!this.modes.has(path)) this.modes.set(path, 0o644)
    return Promise.resolve()
  }

  rename = (from: string, to: string): Promise<void> => {
    const content = this.files.get(from)
    if (content === undefined) return Promise.reject(new Error(`нет файла ${from}`))
    this.files.set(to, content)
    this.files.delete(from)
    const mode = this.modes.get(from)
    if (mode !== undefined) {
      this.modes.delete(from)
      this.modes.set(to, mode)
    }
    return Promise.resolve()
  }

  mkdir = (path: string, mode: number): Promise<void> => {
    this.dirs.push({ path, mode })
    return Promise.resolve()
  }

  exists = (path: string): Promise<boolean> => Promise.resolve(this.files.has(path))

  remove = (path: string): Promise<void> => {
    this.removed.push(path)
    this.files.delete(path)
    return Promise.resolve()
  }

  stat = (path: string): Promise<FileInfo | null> =>
    Promise.resolve(
      this.files.has(path)
        ? { mode: this.modes.get(path) ?? 0o644, uid: 0, gid: 0 }
        : null,
    )

  chmod = (path: string, mode: number): Promise<void> => {
    this.modes.set(path, mode)
    return Promise.resolve()
  }

  chown = (path: string, uid: number, gid: number): Promise<void> => {
    this.owners.set(path, { uid, gid })
    return Promise.resolve()
  }

  confirm = (question: string): Promise<boolean> => {
    this.confirmQuestions.push(question)
    return Promise.resolve(this.confirmAnswer)
  }

  out = (text: string): void => {
    this.outText.push(text)
  }

  err = (text: string): void => {
    this.errText.push(text)
  }

  sleep = (ms: number): Promise<void> => {
    this.sleeps.push(ms)
    return Promise.resolve()
  }
}

const NGINX_MAIN = 'http {\n    include /etc/nginx/conf.d/*.conf;\n}\n'

const SITE_TEXT = `server {
    listen 80;
    server_name example.ru www.example.ru;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name example.ru www.example.ru;
    root /var/www/example;
}
`

function nginxDump(sitePath = SITE_CONF): string {
  return (
    `# configuration file ${NGINX_CONF}:\n${NGINX_MAIN}` +
    `# configuration file ${sitePath}:\n`
  )
}

function nginxHandler(options: { validate?: boolean; reload?: boolean; dump?: string } = {}) {
  const validate = options.validate ?? true
  const reload = options.reload ?? true
  const dump = options.dump ?? nginxDump()
  return (cmd: string, args: readonly string[]): ExecResult => {
    if (cmd === 'nginx' && args[0] === '-T') return ok(dump)
    if (cmd === 'nginx' && args[0] === '-t') {
      return validate ? ok('test is successful') : bad('nginx: [emerg] unknown directive')
    }
    if (cmd === 'nginx' && args[0] === '-s') return ok()
    if (cmd === 'systemctl') return reload ? ok() : bad('Job for nginx.service failed')
    if (cmd === 'caddy') return bad('caddy: not found', 'missing')
    return bad('not found', 'missing')
  }
}

function caddyHandler(validate = true) {
  return (cmd: string, args: readonly string[]): ExecResult => {
    if (cmd === 'nginx') return bad('nginx: not found', 'missing')
    if (cmd === 'caddy' && args[0] === 'version') return ok('v2.8.4')
    if (cmd === 'caddy' && args[0] === 'validate') {
      return validate ? ok('Valid configuration') : bad('Caddyfile: unknown directive')
    }
    if (cmd === 'systemctl') return ok()
    return bad('not found', 'missing')
  }
}

function statusReport(ids: readonly string[], status: Status): JsonReport {
  return {
    version: 'test',
    host: 'test',
    startedAt: '2026-11-07T00:00:00.000Z',
    checks: ids.map((id) => ({
      id,
      section: 5,
      severity: 'medium',
      status,
      findings: [],
      fix: '',
    })),
    site: { stacks: ['nginx'], csp: CSP },
  }
}

/** Первый вызов аудита — проблема, последующие (перепроверка) — уже исправлено */
function auditThenFixed(): (checks: readonly Check[], domain: string) => Promise<JsonReport> {
  let calls = 0
  return (checks: readonly Check[], _domain: string) => {
    calls += 1
    return Promise.resolve(
      statusReport(
        checks.map((check) => check.id),
        calls === 1 ? 'warn' : 'ok',
      ),
    )
  }
}

function args(overrides: Partial<FixArgs> = {}): FixArgs {
  return { domain: 'example.ru', yes: true, dryRun: false, json: false, ...overrides }
}

function allowAccess(): (domain: string) => Promise<unknown> {
  return () => Promise.resolve({ allowed: true })
}

describe('diff без зависимостей', () => {
  test('вставка строки даёт unified diff с контекстом', () => {
    const diff = unifiedDiff('/etc/nginx/site.conf', 'a\nb\nc\n', 'a\nb\nx\nc\n')
    expect(diff).toContain('--- a/etc/nginx/site.conf')
    expect(diff).toContain('+++ b/etc/nginx/site.conf')
    expect(diff).toContain('+x')
  })

  test('создание файла — от /dev/null', () => {
    const diff = unifiedDiff('/etc/nginx/new.conf', null, 'a\n')
    expect(diff).toContain('--- /dev/null')
    expect(diff).toContain('+a')
  })

  test('без изменений diff пуст', () => {
    expect(diffLines('a\nb\n', 'a\nb\n').every((op) => op.type === 'equal')).toBe(true)
    expect(unifiedDiff('/x', 'a\n', 'a\n')).toBe('')
  })
})

describe('nginx: разбор и план', () => {
  test('из server-блоков с доменом выбирает только 443', () => {
    const servers = serversForDomain({ path: SITE_CONF, text: SITE_TEXT }, 'example.ru')
    expect(servers).toHaveLength(2)
    const plan = planNginxFix({
      domain: 'example.ru',
      checks: ['web.headers'],
      csp: CSP,
      files: [{ path: SITE_CONF, text: SITE_TEXT }],
      httpIncludesConfD: true,
      snippetBefore: null,
      ratelimitBefore: null,
    })
    const siteEdit = plan.edits.find((edit) => edit.path === SITE_CONF)
    expect(siteEdit).toBeDefined()
    expect(siteEdit?.after.split(NGINX_INCLUDE)).toHaveLength(2)
    expect(siteEdit?.after).toContain(NGINX_INCLUDE)
  })

  test('wildcard-родитель закрывает домен', () => {
    expect(matchesDomain('*.example.ru', 'example.ru')).toBe(true)
    expect(matchesDomain('*.example.ru', 'www.example.ru')).toBe(true)
    expect(matchesDomain('other.ru', 'example.ru')).toBe(false)
  })

  test('уже заданный add_header не дублируется', () => {
    const text = `server {
    listen 443 ssl;
    server_name manual.example.ru;
    add_header X-Frame-Options "DENY" always;
}
`
    const plan = planNginxFix({
      domain: 'manual.example.ru',
      checks: ['web.headers'],
      csp: CSP,
      files: [{ path: SITE_CONF, text }],
      httpIncludesConfD: true,
      snippetBefore: null,
      ratelimitBefore: null,
    })
    expect(plan.edits).toHaveLength(0)
    expect(plan.skipped.some((item) => item.reason === 'already')).toBe(true)
    expect(plan.skipped.some((item) => item.detail.includes('уже задано вручную'))).toBe(true)
  })

  test('в http нет conf.d — ratelimit только рецептом', () => {
    const plan = planNginxFix({
      domain: 'example.ru',
      checks: ['web.ratelimit'],
      csp: CSP,
      files: [{ path: SITE_CONF, text: SITE_TEXT }],
      httpIncludesConfD: false,
      snippetBefore: null,
      ratelimitBefore: null,
    })
    expect(plan.edits).toHaveLength(0)
    expect(plan.skipped.some((item) => item.reason === 'no-conf-d')).toBe(true)
  })

  test('повторный fix другой проверки не теряет прежние директивы сниппета', () => {
    const first = planNginxFix({
      domain: 'example.ru',
      checks: ['web.headers'],
      csp: CSP,
      files: [{ path: SITE_CONF, text: SITE_TEXT }],
      httpIncludesConfD: true,
      snippetBefore: null,
      ratelimitBefore: null,
    })
    const snippet = first.edits.find((edit) => edit.path === NGINX_SNIPPET_PATH)?.after ?? ''
    expect(snippet).toContain('Strict-Transport-Security')

    const second = planNginxFix({
      domain: 'example.ru',
      checks: ['web.sourcemaps'],
      csp: CSP,
      files: [{ path: SITE_CONF, text: SITE_TEXT }],
      httpIncludesConfD: true,
      snippetBefore: snippet,
      ratelimitBefore: null,
    })
    const updated =
      second.edits.find((edit) => edit.path === NGINX_SNIPPET_PATH)?.after ?? snippet
    expect(updated).toContain('Strict-Transport-Security')
    expect(updated).toContain('location ~* \\.map$')
  })

  test('add_header в location: заголовки кладём отдельным include внутрь location', () => {
    const text = `server {
    listen 443 ssl;
    server_name example.ru;

    location / {
        add_header Cache-Control "no-cache";
        try_files $uri $uri/ =404;
    }
}
`
    const plan = planNginxFix({
      domain: 'example.ru',
      checks: ['web.headers'],
      csp: CSP,
      files: [{ path: SITE_CONF, text }],
      httpIncludesConfD: true,
      snippetBefore: null,
      headersSnippetBefore: null,
      ratelimitBefore: null,
    })
    const headersSnippet = plan.edits.find((edit) => edit.path === NGINX_HEADERS_SNIPPET_PATH)
    expect(headersSnippet?.after).toContain('Strict-Transport-Security')
    const siteEdit = plan.edits.find((edit) => edit.path === SITE_CONF)
    expect(siteEdit?.after).toContain(NGINX_HEADERS_INCLUDE)
    expect(siteEdit?.after).toContain('add_header Cache-Control "no-cache"')
  })

  test('однострочный server-блок: include остаётся внутри блока и не комментирует хвост', () => {
    const text = 'server { listen 443 ssl; server_name example.ru; root /var/www; }\n'
    const plan = planNginxFix({
      domain: 'example.ru',
      checks: ['web.headers'],
      csp: CSP,
      files: [{ path: SITE_CONF, text }],
      httpIncludesConfD: true,
      snippetBefore: null,
      headersSnippetBefore: null,
      ratelimitBefore: null,
    })
    const siteEdit = plan.edits.find((edit) => edit.path === SITE_CONF)?.after ?? ''
    expect(siteEdit).toContain(`${NGINX_INCLUDE}\n`)
    expect(siteEdit.indexOf(NGINX_INCLUDE)).toBeLessThan(siteEdit.indexOf('root /var/www'))
    expect(siteEdit.indexOf(NGINX_INCLUDE)).toBeLessThan(siteEdit.lastIndexOf('}'))
  })

  test('повторный fix не дублирует include заголовков в location', () => {
    const text = `server {
    listen 443 ssl;
    server_name example.ru;

    location / {
        add_header Cache-Control "no-cache";
        try_files $uri $uri/ =404;
    }
}
`
    const first = planNginxFix({
      domain: 'example.ru',
      checks: ['web.headers'],
      csp: CSP,
      files: [{ path: SITE_CONF, text }],
      httpIncludesConfD: true,
      snippetBefore: null,
      headersSnippetBefore: null,
      ratelimitBefore: null,
    })
    const siteAfter = first.edits.find((edit) => edit.path === SITE_CONF)?.after ?? text
    const snippetAfter =
      first.edits.find((edit) => edit.path === NGINX_SNIPPET_PATH)?.after ?? ''
    const headersAfter =
      first.edits.find((edit) => edit.path === NGINX_HEADERS_SNIPPET_PATH)?.after ?? ''
    const second = planNginxFix({
      domain: 'example.ru',
      checks: ['web.headers'],
      csp: CSP,
      files: [{ path: SITE_CONF, text: siteAfter }],
      httpIncludesConfD: true,
      snippetBefore: snippetAfter,
      headersSnippetBefore: headersAfter,
      ratelimitBefore: null,
    })
    expect(second.edits).toHaveLength(0)
  })

  test('conf.d считается только при include, который подхватит наш файл', () => {
    expect(
      httpIncludesConfD([{ path: NGINX_CONF, text: 'http { include /etc/nginx/conf.d/*.conf; }' }]),
    ).toBe(true)
    expect(
      httpIncludesConfD([{ path: NGINX_CONF, text: 'http { include /etc/nginx/conf.d/foo.conf; }' }]),
    ).toBe(false)
  })

  test('parseNginxDump берёт пути файлов', () => {
    expect(parseNginxDump(nginxDump())).toEqual([NGINX_CONF, SITE_CONF])
  })
})

describe('Caddy: разбор и план', () => {
  const text = `example.ru {
    reverse_proxy localhost:3000
}

www.example.ru, example.ru {
    reverse_proxy localhost:3001
}
`

  test('несколько доменов в адресе и import в каждом блоке', () => {
    const plan = planCaddyFix({
      domain: 'example.ru',
      checks: ['web.headers', 'web.banner'],
      csp: CSP,
      text,
    })
    expect(plan.edits).toHaveLength(1)
    const after = plan.edits[0]?.after ?? ''
    expect(after.split('import borodatych-security')).toHaveLength(3)
    expect(after).toContain('(borodatych-security)')
  })

  test('повторный план пуст: сниппет и import уже на месте', () => {
    const first = planCaddyFix({
      domain: 'example.ru',
      checks: ['web.headers', 'web.banner'],
      csp: CSP,
      text,
    })
    const second = planCaddyFix({
      domain: 'example.ru',
      checks: ['web.headers', 'web.banner'],
      csp: CSP,
      text: first.edits[0]?.after ?? text,
    })
    expect(second.edits).toHaveLength(0)
  })

  test('наш сниппет без маркера не трогаем', () => {
    const foreign = `(borodatych-security) {\n    header -Server\n}\n\nexample.ru {\n}\n`
    const plan = planCaddyFix({
      domain: 'example.ru',
      checks: ['web.headers'],
      csp: CSP,
      text: foreign,
    })
    expect(plan.edits).toHaveLength(0)
    expect(plan.skipped.some((item) => item.reason === 'partial')).toBe(true)
  })

  test('parseCaddyfile видит сайты и сниппет', () => {
    const parsed = parseCaddyfile(`${caddySnippetFile(['web.banner'], CSP)}${text}`)
    expect(parsed.some((block) => block.kind === 'snippet')).toBe(true)
    expect(parsed.filter((block) => block.kind === 'site')).toHaveLength(2)
  })

  test('повторный fix другой проверки не теряет прежние директивы сниппета', () => {
    const first = planCaddyFix({
      domain: 'example.ru',
      checks: ['web.headers'],
      csp: CSP,
      text,
    })
    const withHeaders = first.edits[0]?.after ?? text
    const second = planCaddyFix({
      domain: 'example.ru',
      checks: ['web.sourcemaps'],
      csp: CSP,
      text: withHeaders,
    })
    const after = second.edits[0]?.after ?? withHeaders
    expect(after).toContain('Strict-Transport-Security')
    expect(after).toContain('@borodatych_security_maps path *.map')
  })

  test('чужой @maps не мешает защите sourcemaps и не даёт дубль матчера', () => {
    const site = `stand.test {
    @maps path /health
    respond @maps "ok"
    respond "ok"
}
`
    const plan = planCaddyFix({
      domain: 'stand.test',
      checks: ['web.sourcemaps'],
      csp: CSP,
      text: site,
    })
    expect(plan.edits).toHaveLength(1)
    const after = plan.edits[0]?.after ?? ''
    expect(after).toContain('@borodatych_security_maps path *.map')
    expect(after).toContain('respond @borodatych_security_maps 404')
    expect(after).toContain('@maps path /health')
  })

  test('Caddy ratelimit — рецепт, не правка', () => {
    const plan = planCaddyFix({
      domain: 'example.ru',
      checks: ['web.ratelimit'],
      csp: CSP,
      text,
    })
    expect(plan.edits).toHaveLength(0)
    expect(plan.skipped[0]?.reason).toBe('unsupported')
  })
})

function nginxCtx(handler = nginxHandler()): FakeCtx {
  const ctx = new FakeCtx(handler)
  ctx.files.set(NGINX_CONF, NGINX_MAIN)
  ctx.files.set(SITE_CONF, SITE_TEXT)
  return ctx
}

describe('fix: полный прогон на подменах', () => {
  test('dry-run: план и дифф, ни одной записи', async () => {
    const ctx = nginxCtx()
    const code = await runFix({
      ctx,
      args: args({ dryRun: true }),
      deps: {
        requireAccess: allowAccess(),
        auditSite: () => Promise.resolve(statusReport(['web.headers'], 'warn')),
      },
    })
    const output = ctx.outText.join('')
    expect(code).toBe(0)
    expect(output).toContain('--- a/etc/nginx/conf.d/example.ru.conf')
    expect(output).toContain(`+    ${NGINX_INCLUDE}`)
    expect(output).toContain('--dry-run')
    expect(ctx.writes).toHaveLength(0)
  })

  test('повторный прогон даёт пустой план', async () => {
    const ctx = nginxCtx()
    const first = await runFix({
      ctx,
      args: args(),
      deps: { requireAccess: allowAccess(), auditSite: auditThenFixed() },
    })
    expect(first).toBe(0)
    const writesAfterFirst = ctx.writes.length
    ctx.outText.length = 0
    const second = await runFix({
      ctx,
      args: args(),
      deps: { requireAccess: allowAccess(), auditSite: auditThenFixed() },
    })
    expect(second).toBe(0)
    expect(ctx.writes).toHaveLength(writesAfterFirst)
    expect(ctx.outText.join('')).not.toContain('Дифф')
  })

  test('провал проверки конфига: все файлы восстановлены, созданные удалены', async () => {
    const ctx = nginxCtx(nginxHandler({ validate: false }))
    const code = await runFix({
      ctx,
      args: args(),
      deps: {
        requireAccess: allowAccess(),
        auditSite: () => Promise.resolve(statusReport(['web.headers'], 'warn')),
      },
    })
    expect(code).toBe(1)
    expect(ctx.files.get(SITE_CONF)).toBe(SITE_TEXT)
    expect(ctx.files.has(NGINX_SNIPPET_PATH)).toBe(false)
    expect(ctx.errText.join('')).toContain('вернул файлы из бэкапа')
  })

  test('провал reload: откат', async () => {
    const ctx = nginxCtx(nginxHandler({ reload: false }))
    const code = await runFix({
      ctx,
      args: args(),
      deps: {
        requireAccess: allowAccess(),
        auditSite: () => Promise.resolve(statusReport(['web.headers'], 'warn')),
      },
    })
    expect(code).toBe(1)
    expect(ctx.files.get(SITE_CONF)).toBe(SITE_TEXT)
    expect(ctx.files.has(NGINX_SNIPPET_PATH)).toBe(false)
    expect(ctx.errText.join('')).toContain('не перезагрузилась')
  })

  test('нет доступа — ни одного вызова write', async () => {
    const ctx = nginxCtx()
    const code = await runFix({
      ctx,
      args: args(),
      deps: {
        requireAccess: () => Promise.reject(new AccessError('denied', 'нет доступа')),
        auditSite: () => Promise.resolve(statusReport(['web.headers'], 'warn')),
      },
    })
    expect(code).toBe(2)
    expect(ctx.writes).toHaveLength(0)
    expect(ctx.errText.join('')).toContain('нет доступа')
  })

  test('не root — ошибка до любых действий', async () => {
    const ctx = nginxCtx()
    ctx.uid = 1000
    const code = await runFix({
      ctx,
      args: args(),
      deps: { requireAccess: allowAccess(), auditSite: () => Promise.resolve(statusReport([], 'ok')) },
    })
    expect(code).toBe(2)
    expect(ctx.writes).toHaveLength(0)
    expect(ctx.errText.join('')).toContain('sudo')
  })

  test('нет TTY и нет --yes — отказ без write', async () => {
    const ctx = nginxCtx()
    ctx.stdinIsTTY = false
    const code = await runFix({
      ctx,
      args: args({ yes: false }),
      deps: {
        requireAccess: allowAccess(),
        auditSite: () => Promise.resolve(statusReport(['web.headers'], 'warn')),
      },
    })
    expect(code).toBe(2)
    expect(ctx.writes).toHaveLength(0)
    expect(ctx.errText.join('')).toContain('--yes')
  })

  test('откат по манифесту возвращает файлы и удаляет созданные', async () => {
    const ctx = nginxCtx()
    const code = await runFix({
      ctx,
      args: args(),
      deps: { requireAccess: allowAccess(), auditSite: auditThenFixed() },
    })
    expect(code).toBe(0)
    const backupDir = `/var/backups/borodatych-security/${ctx.now.toISOString()}`
    expect(ctx.files.has(backupDir + '/manifest.json')).toBe(true)
    expect(ctx.files.get(SITE_CONF)).not.toBe(SITE_TEXT)

    const rolled = await runFix({
      ctx,
      args: args({ rollback: backupDir }),
      deps: { requireAccess: allowAccess() },
    })
    expect(rolled).toBe(0)
    expect(ctx.files.get(SITE_CONF)).toBe(SITE_TEXT)
    expect(ctx.files.has(NGINX_SNIPPET_PATH)).toBe(false)
  })

  test('Caddy: план, применение и перепроверка', async () => {
    const text = 'example.ru {\n    reverse_proxy localhost:3000\n}\n'
    const ctx = new FakeCtx(caddyHandler())
    ctx.files.set(CADDYFILE, text)
    const code = await runFix({
      ctx,
      args: args(),
      deps: {
        requireAccess: allowAccess(),
        auditSite: () =>
          Promise.resolve({
            ...statusReport(['web.banner'], 'warn'),
            site: { stacks: ['caddy'], csp: CSP },
          }),
      },
    })
    // перепроверка возвращает warn, поэтому итог 1, но правки применены
    expect(code).toBe(1)
    const after = ctx.files.get(CADDYFILE) ?? ''
    expect(after).toContain('(borodatych-security)')
    expect(after).toContain('import borodatych-security')
  })

  test('systemctl нет — nginx перезагружается через nginx -s reload', async () => {
    const ctx = nginxCtx((cmd, commandArgs) => {
      if (cmd === 'nginx' && commandArgs[0] === '-T') return ok(nginxDump())
      if (cmd === 'nginx' && commandArgs[0] === '-t') return ok('test is successful')
      if (cmd === 'nginx' && commandArgs[0] === '-s') return ok()
      if (cmd === 'systemctl') return bad('systemctl: not found', 'missing')
      if (cmd === 'caddy') return bad('caddy: not found', 'missing')
      return bad('not found', 'missing')
    })
    const code = await runFix({
      ctx,
      args: args(),
      deps: { requireAccess: allowAccess(), auditSite: auditThenFixed() },
    })
    expect(code).toBe(0)
    const reload = ctx.commands.find(
      (command) => command.cmd === 'nginx' && command.args[0] === '-s',
    )
    expect(reload?.args).toEqual(['-s', 'reload'])
  })

  test('systemctl нет — caddy перезагружается через caddy reload', async () => {
    const text = 'example.ru {\n    reverse_proxy localhost:3000\n}\n'
    const ctx = new FakeCtx((cmd, commandArgs) => {
      if (cmd === 'nginx') return bad('nginx: not found', 'missing')
      if (cmd === 'caddy' && commandArgs[0] === 'version') return ok('v2.8.4')
      if (cmd === 'caddy' && commandArgs[0] === 'validate') return ok('Valid configuration')
      if (cmd === 'caddy' && commandArgs[0] === 'reload') return ok()
      if (cmd === 'systemctl') return bad('systemctl: not found', 'missing')
      return bad('not found', 'missing')
    })
    ctx.files.set(CADDYFILE, text)
    const code = await runFix({
      ctx,
      args: args(),
      deps: {
        requireAccess: allowAccess(),
        auditSite: () =>
          Promise.resolve({
            ...statusReport(['web.banner'], 'warn'),
            site: { stacks: ['caddy'], csp: CSP },
          }),
      },
    })
    // перепроверка на подмене возвращает warn, но reload должен быть прямым
    expect(code).toBe(1)
    const reload = ctx.commands.find(
      (command) => command.cmd === 'caddy' && command.args[0] === 'reload',
    )
    expect(reload?.args).toEqual(['reload', '--config', CADDYFILE, '--adapter', 'caddyfile'])
  })

  test('--json: в stdout только машинный итог', async () => {
    const ctx = nginxCtx()
    const code = await runFix({
      ctx,
      args: args({ dryRun: true, json: true }),
      deps: {
        requireAccess: allowAccess(),
        auditSite: () => Promise.resolve(statusReport(['web.headers'], 'warn')),
      },
    })
    expect(code).toBe(0)
    const parsed = JSON.parse(ctx.outText.join('')) as {
      ok: boolean
      dryRun: boolean
      server: string
      changes: unknown[]
    }
    expect(parsed.ok).toBe(true)
    expect(parsed.dryRun).toBe(true)
    expect(parsed.server).toBe('nginx')
    expect(parsed.changes.length).toBeGreaterThan(0)
  })

  test('откат без манифеста — ошибка и код 1', async () => {
    const ctx = nginxCtx()
    const code = await runFix({
      ctx,
      args: args({ rollback: '/var/backups/borodatych-security/none' }),
      deps: {},
    })
    expect(code).toBe(1)
    expect(ctx.errText.join('')).toContain('manifest.json')
  })

  test('все охваченные проверки перечислены в константе', () => {
    expect([...AUTO_FIX_CHECKS]).toEqual([
      'web.headers',
      'web.banner',
      'web.sourcemaps',
      'web.ratelimit',
    ])
  })
})
