import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { FixArgs } from '../../src/fix/args'
import { AUTO_FIX_CHECKS, runFix, type FixDeps } from '../../src/fix/run'
import type { Stack } from '../../src/recipes/types'
import type { Check, JsonReport, Status } from '../../src/types'
import {
  burstStatuses,
  CADDY_IMAGE,
  createStandCtx,
  headerValue,
  hasHeader,
  httpHeaders,
  httpStatus,
  must,
  NGINX_IMAGE,
  prepareRunDir,
  probeHeaders,
  sh,
  STAND_ROOT,
  type StandCtx,
} from './util'

const DOMAIN = 'stand.test'
const CSP = "default-src 'self'; object-src 'none'; frame-ancestors 'self'"
const ONLY: string[] = [...AUTO_FIX_CHECKS]

const NGINX_HTTP_PORT = 18080
const NGINX_HTTPS_PORT = 18443
const CADDY_HTTPS_PORT = 28443
const CADDY_HTTP_PORT = 28080
const CADDY_ALT_PORT = 28081

const NGINX_SITE_PATH = '/etc/nginx/conf.d/api-stand.conf'
const NGINX_SNIPPET_PATH = '/etc/nginx/snippets/borodatych-security.conf'
const NGINX_HEADERS_SNIPPET_PATH = '/etc/nginx/snippets/borodatych-security-headers.conf'
const NGINX_RATELIMIT_PATH = '/etc/nginx/conf.d/borodatych-security-ratelimit.conf'
const CADDYFILE_PATH = '/etc/caddy/Caddyfile'

const REQUIRED_HEADERS = [
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'x-frame-options',
  'content-security-policy-report-only',
] as const

const PREFIX = `borodatych-stand-${String(process.pid)}`
const NETWORK = `${PREFIX}-net`
const containers: string[] = []

let checksPassed = 0

function check(condition: boolean, what: string, detail = ''): void {
  if (!condition) {
    throw new Error(`ПРОВАЛ: ${what}${detail.length > 0 ? ` (${detail})` : ''}`)
  }
  checksPassed += 1
  console.log(`  ✓ ${what}`)
}

function cleanup(): void {
  for (const name of containers) sh(['docker', 'rm', '-f', name])
  containers.length = 0
  sh(['docker', 'network', 'rm', NETWORK])
}

function ensureImage(image: string): void {
  if (!sh(['docker', 'image', 'inspect', image]).ok) {
    must(['docker', 'pull', image], `docker pull ${image}`)
  }
}

function fixArgs(): FixArgs {
  return { domain: DOMAIN, only: [...ONLY], yes: true, dryRun: false, json: false }
}

function rollbackArgs(dir: string): FixArgs {
  return { rollback: dir, yes: true, dryRun: false, json: false }
}

function allowAccess(): Promise<unknown> {
  return Promise.resolve({ allowed: true })
}

function makeReport(ids: readonly string[], status: Status, stacks: readonly Stack[]): JsonReport {
  return {
    version: 'stand',
    host: 'stand',
    startedAt: '2026-11-07T12:00:00.000Z',
    checks: ids.map((id) => ({
      id,
      section: 5,
      severity: 'medium',
      status,
      findings: [],
      fix: '',
    })),
    site: { stacks: [...stacks], csp: CSP },
  }
}

/** Первый аудит видит проблемы, перепроверка внутри fix — уже исправлено */
function auditMock(stacks: readonly Stack[]): NonNullable<FixDeps['auditSite']> {
  let calls = 0
  return (checks: readonly Check[]) => {
    calls += 1
    const status: Status = calls === 1 ? 'warn' : 'ok'
    return Promise.resolve(makeReport(checks.map((checkItem) => checkItem.id), status, stacks))
  }
}

function runFixOn(ctx: StandCtx, stacks: readonly Stack[]): Promise<number> {
  return runFix({
    ctx,
    args: fixArgs(),
    deps: { requireAccess: allowAccess, auditSite: auditMock(stacks) },
  })
}

function outputOf(ctx: StandCtx): string {
  return `${ctx.outText.join('')}${ctx.errText.join('')}`
}

async function waitFor(what: string, predicate: () => boolean, attempts = 80): Promise<void> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (predicate()) return
    await Bun.sleep(250)
  }
  throw new Error(`не дождались: ${what}`)
}

function startNetwork(): void {
  sh(['docker', 'network', 'rm', NETWORK])
  must(['docker', 'network', 'create', NETWORK], 'docker network create')
}

function writeNginxStand(dir: string): void {
  mkdirSync(join(dir, 'conf.d'), { recursive: true })
  mkdirSync(join(dir, 'certs'), { recursive: true })
  mkdirSync(join(dir, 'www'), { recursive: true })

  must(
    [
      'openssl',
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      join(dir, 'certs', 'stand.key'),
      '-out',
      join(dir, 'certs', 'stand.crt'),
      '-days',
      '2',
      '-subj',
      '/CN=stand.test',
    ],
    'openssl: самоподписанный сертификат',
  )

  const site = `server {
    listen 80;
    server_name stand.test;

    root /var/www/stand;
    location / {
        try_files $uri $uri/ =404;
    }
}

server { listen 443 ssl; server_name stand.test; root /var/www/stand; ssl_certificate /etc/nginx/certs/stand.crt; ssl_certificate_key /etc/nginx/certs/stand.key; location / { add_header Cache-Control "no-cache"; try_files $uri $uri/ =404; } }
`
  writeFileSync(join(dir, 'conf.d', 'api-stand.conf'), site, 'utf8')
  writeFileSync(join(dir, 'www', 'index.html'), '<!doctype html><title>stand</title>\n', 'utf8')
  writeFileSync(join(dir, 'www', 'app.js'), '//# sourceMappingURL=app.js.map\n', 'utf8')
  writeFileSync(join(dir, 'www', 'app.js.map'), '{"version":3,"sources":["app.ts"]}\n', 'utf8')
}

function startNginx(dir: string): string {
  const name = `${PREFIX}-nginx`
  sh(['docker', 'rm', '-f', name])
  must(
    [
      'docker',
      'run',
      '-d',
      '--name',
      name,
      '--network',
      NETWORK,
      '-p',
      `127.0.0.1:${String(NGINX_HTTP_PORT)}:80`,
      '-p',
      `127.0.0.1:${String(NGINX_HTTPS_PORT)}:443`,
      '-v',
      `${join(dir, 'conf.d')}:/etc/nginx/conf.d:rw`,
      '-v',
      `${join(dir, 'certs')}:/etc/nginx/certs:ro`,
      '-v',
      `${join(dir, 'www')}:/var/www/stand:ro`,
      NGINX_IMAGE,
    ],
    'docker run nginx',
  )
  containers.push(name)
  return name
}

function writeCaddyStand(dir: string): void {
  mkdirSync(join(dir, 'data'), { recursive: true })
  mkdirSync(join(dir, 'config'), { recursive: true })
  const text = `{
    admin localhost:2019
}

stand.test {
    tls internal
    @maps path /health
    respond @maps "ok"
    respond "ok"
}

http://stand.test:8080 {
    respond "ok"
}
`
  writeFileSync(join(dir, 'Caddyfile'), text, 'utf8')
}

function startCaddy(dir: string): string {
  const name = `${PREFIX}-caddy`
  sh(['docker', 'rm', '-f', name])
  must(
    [
      'docker',
      'run',
      '-d',
      '--name',
      name,
      '--network',
      NETWORK,
      '-p',
      `127.0.0.1:${String(CADDY_HTTPS_PORT)}:443`,
      '-p',
      `127.0.0.1:${String(CADDY_HTTP_PORT)}:80`,
      '-p',
      `127.0.0.1:${String(CADDY_ALT_PORT)}:8080`,
      '-v',
      `${dir}:/etc/caddy:rw`,
      '-v',
      `${join(dir, 'data')}:/data`,
      '-v',
      `${join(dir, 'config')}:/config`,
      CADDY_IMAGE,
    ],
    'docker run caddy',
  )
  containers.push(name)
  return name
}

function checkHeaders(port: number, label: string): void {
  const response = httpHeaders(port)
  check(response.status === 200, `${label}: GET / отвечает 200`, `получили ${String(response.status)}`)
  for (const name of REQUIRED_HEADERS) {
    check(hasHeader(response.headers, name), `${label}: заголовок ${name} присутствует`)
  }
}

function checkSourcemapHidden(port: number, label: string): void {
  const response = httpHeaders(port, '/app.js.map')
  check(
    response.status === 404,
    `${label}: GET /app.js.map → 404`,
    `получили ${String(response.status)}`,
  )
}

function readFileOrNull(ctx: StandCtx, path: string): Promise<string | null> {
  return ctx.read(path)
}

async function snapshot(ctx: StandCtx, paths: readonly string[]): Promise<Map<string, string | null>> {
  const files = new Map<string, string | null>()
  for (const path of paths) files.set(path, await readFileOrNull(ctx, path))
  return files
}

function sameSnapshot(
  left: Map<string, string | null>,
  right: Map<string, string | null>,
): boolean {
  for (const [path, value] of left) {
    if ((right.get(path) ?? null) !== value) return false
  }
  return true
}

function direct(ctx: StandCtx, cmd: string, args: readonly string[]): Promise<{ ok: boolean; text: string }> {
  return ctx.execRaw(cmd, args).then((result) => ({
    ok: result.ok,
    text: (result.stderr.trim() || result.stdout.trim()).slice(0, 400),
  }))
}

async function runNginx(): Promise<void> {
  console.log('\n== nginx ==')
  const dir = prepareRunDir('nginx')
  writeNginxStand(dir)
  const container = startNginx(dir)
  const tempDir = join(dir, 'tmp')
  mkdirSync(tempDir, { recursive: true })

  await waitFor('nginx отвечает по HTTPS', () => {
    if (!sh(['docker', 'exec', container, 'nginx', '-t']).ok) return false
    return probeHeaders(NGINX_HTTPS_PORT)?.status === 200
  })
  console.log('  контейнер nginx готов')
  const nginxSystemctl = sh(['docker', 'exec', container, 'systemctl', '--version'])
  const nginxSystemctlText = `${nginxSystemctl.stdout}${nginxSystemctl.stderr}`
  check(
    !nginxSystemctl.ok && /not found|executable file not found/i.test(nginxSystemctlText),
    'nginx: systemctl в контейнере нет — reload пойдёт напрямую',
    `код ${String(nginxSystemctl.code)}: ${nginxSystemctlText.trim()}`,
  )

  const original = await snapshot(createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T12:00:00.000Z'),
  }), [NGINX_SITE_PATH, NGINX_SNIPPET_PATH, NGINX_HEADERS_SNIPPET_PATH, NGINX_RATELIMIT_PATH])

  const before = httpHeaders(NGINX_HTTPS_PORT, '/app.js.map')
  check(before.status === 200, 'nginx: до fix /app.js.map отдаётся', `получили ${String(before.status)}`)
  check(
    !hasHeader(httpHeaders(NGINX_HTTPS_PORT).headers, 'strict-transport-security'),
    'nginx: до fix HSTS нет',
  )

  const ctx = createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T12:00:00.000Z'),
  })
  const code = await runFixOn(ctx, ['nginx'])
  check(code === 0, 'fix: nginx применился без ошибок', outputOf(ctx).slice(-800))

  const nginxTest = await direct(ctx, 'nginx', ['-t'])
  check(nginxTest.ok, 'nginx -t после fix успешен', nginxTest.text)
  // reload асинхронный: ждём, когда новые worker'ы начнут отдавать заголовки
  await waitFor('nginx: HSTS появился после reload', () => {
    const response = probeHeaders(NGINX_HTTPS_PORT)
    return response !== null && hasHeader(response.headers, 'strict-transport-security')
  })
  checkHeaders(NGINX_HTTPS_PORT, 'nginx')

  const server = headerValue(httpHeaders(NGINX_HTTPS_PORT).headers, 'server')
  check(server === 'nginx', 'nginx: Server без версии', `Server: ${server ?? 'нет'}`)
  checkSourcemapHidden(NGINX_HTTPS_PORT, 'nginx')

  const statuses = burstStatuses(NGINX_HTTPS_PORT, 40)
  const limited = statuses.filter((status) => status === 429 || status === 503).length
  check(
    limited > 0,
    'nginx: 40 быстрых запросов дают 429/503',
    `статусы: ${statuses.join(',')}`,
  )

  const paths = [
    NGINX_SITE_PATH,
    NGINX_SNIPPET_PATH,
    NGINX_HEADERS_SNIPPET_PATH,
    NGINX_RATELIMIT_PATH,
  ]
  check(
    (await ctx.read(NGINX_HEADERS_SNIPPET_PATH)) !== null,
    'nginx: создан отдельный сниппет заголовков для location',
  )
  const snapshotBefore = await snapshot(ctx, paths)
  const rerunCtx = createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T12:00:00.000Z'),
  })
  const rerun = await runFixOn(rerunCtx, ['nginx'])
  check(rerun === 0, 'nginx: повторный fix вернул 0', outputOf(rerunCtx).slice(-800))
  check(
    sameSnapshot(snapshotBefore, await snapshot(rerunCtx, paths)),
    'nginx: повторный fix не изменил файлы байт-в-байт',
  )
  check(
    !outputOf(rerunCtx).includes('--- a/'),
    'nginx: повторный план пуст (диффа нет)',
  )

  const backupDir = '/var/backups/borodatych-security/2026-11-07T12:00:00.000Z'
  const rollbackCtx = createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T12:00:00.000Z'),
  })
  const rolled = await runFix({ ctx: rollbackCtx, args: rollbackArgs(backupDir) })
  check(rolled === 0, 'nginx: --rollback вернул 0', outputOf(rollbackCtx).slice(-800))
  check(
    sameSnapshot(original, await snapshot(rollbackCtx, paths)),
    'nginx: --rollback вернул файлы как до fix',
  )
  const afterRollbackTest = await direct(rollbackCtx, 'nginx', ['-t'])
  check(afterRollbackTest.ok, 'nginx -t после отката успешен', afterRollbackTest.text)
  await waitFor('nginx: HSTS исчез после отката', () => {
    const response = probeHeaders(NGINX_HTTPS_PORT)
    return response !== null && !hasHeader(response.headers, 'strict-transport-security')
  })
  check(
    !hasHeader(httpHeaders(NGINX_HTTPS_PORT).headers, 'strict-transport-security'),
    'nginx: после отката HSTS снова нет',
  )
  const serverRolled = headerValue(httpHeaders(NGINX_HTTPS_PORT).headers, 'server')
  check(
    serverRolled?.startsWith('nginx/') === true,
    'nginx: после отката Server снова с версией',
    `Server: ${serverRolled ?? 'нет'}`,
  )

  // Отрицательный случай: настоящий nginx -t, но с битым лишним файлом в conf.d
  const negative = createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T13:00:00.000Z'),
  })
  negative.setValidatorHook(async () => {
    const broken = '/etc/nginx/conf.d/zz-stand-broken.conf'
    await negative.write(broken, 'this_is_not_a_nginx_directive;\n')
    try {
      return await negative.execRaw('nginx', ['-t'])
    } finally {
      await negative.remove(broken)
    }
  })
  const negativeCode = await runFixOn(negative, ['nginx'])
  check(negativeCode === 1, 'nginx: битый конфиг даёт код 1', outputOf(negative).slice(-800))
  check(
    sameSnapshot(original, await snapshot(negative, paths)),
    'nginx: при провале валидации все файлы откатились',
  )
  const negativeTest = await direct(negative, 'nginx', ['-t'])
  check(negativeTest.ok, 'nginx -t после отрицательного случая успешен', negativeTest.text)
  check(
    outputOf(negative).includes('вернул файлы из бэкапа'),
    'nginx: в выводе есть сообщение об откате',
  )
}

async function runCaddy(): Promise<void> {
  console.log('\n== caddy ==')
  const dir = prepareRunDir('caddy')
  writeCaddyStand(dir)
  const container = startCaddy(dir)
  const tempDir = join(dir, 'tmp')
  mkdirSync(tempDir, { recursive: true })

  await waitFor('caddy отвечает по HTTPS', () => {
    if (!sh(['docker', 'exec', container, 'caddy', 'version']).ok) return false
    return probeHeaders(CADDY_HTTPS_PORT)?.status === 200
  })
  console.log('  контейнер caddy готов')
  const caddySystemctl = sh(['docker', 'exec', container, 'systemctl', '--version'])
  const caddySystemctlText = `${caddySystemctl.stdout}${caddySystemctl.stderr}`
  check(
    !caddySystemctl.ok && /not found|executable file not found/i.test(caddySystemctlText),
    'caddy: systemctl в контейнере нет — reload пойдёт напрямую',
    `код ${String(caddySystemctl.code)}: ${caddySystemctlText.trim()}`,
  )

  const original = await snapshot(
    createStandCtx({
      container,
      tempDir,
      now: new Date('2026-11-07T12:00:00.000Z'),
    }),
    [CADDYFILE_PATH],
  )

  check(
    !hasHeader(httpHeaders(CADDY_HTTPS_PORT).headers, 'strict-transport-security'),
    'caddy: до fix HSTS нет',
  )

  const ctx = createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T12:00:00.000Z'),
  })
  const code = await runFixOn(ctx, ['caddy'])
  check(code === 0, 'fix: caddy применился без ошибок', outputOf(ctx).slice(-800))

  const caddyValidate = await direct(ctx, 'caddy', [
    'validate',
    '--config',
    CADDYFILE_PATH,
    '--adapter',
    'caddyfile',
  ])
  check(caddyValidate.ok, 'caddy validate после fix успешен', caddyValidate.text)
  await waitFor('caddy: HSTS появился после reload', () => {
    const response = probeHeaders(CADDY_HTTPS_PORT)
    return response !== null && hasHeader(response.headers, 'strict-transport-security')
  })
  checkHeaders(CADDY_HTTPS_PORT, 'caddy')

  const server = headerValue(httpHeaders(CADDY_HTTPS_PORT).headers, 'server')
  check(server === null, 'caddy: заголовка Server нет', `Server: ${server ?? 'нет'}`)
  checkSourcemapHidden(CADDY_HTTPS_PORT, 'caddy')

  const alt = httpStatus({ url: `http://127.0.0.1:${String(CADDY_ALT_PORT)}`, host: 'stand.test:8080' })
  check(alt === 200, 'caddy: блок http://stand.test:8080 отвечает 200', `получили ${String(alt)}`)

  const paths = [CADDYFILE_PATH]
  const snapshotBefore = await snapshot(ctx, paths)
  const rerunCtx = createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T12:00:00.000Z'),
  })
  const rerun = await runFixOn(rerunCtx, ['caddy'])
  check(rerun === 0, 'caddy: повторный fix вернул 0', outputOf(rerunCtx).slice(-800))
  check(
    sameSnapshot(snapshotBefore, await snapshot(rerunCtx, paths)),
    'caddy: повторный fix не изменил Caddyfile байт-в-байт',
  )
  check(
    !outputOf(rerunCtx).includes('--- a/'),
    'caddy: повторный план пуст (диффа нет)',
  )

  const backupDir = '/var/backups/borodatych-security/2026-11-07T12:00:00.000Z'
  const rollbackCtx = createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T12:00:00.000Z'),
  })
  const rolled = await runFix({ ctx: rollbackCtx, args: rollbackArgs(backupDir) })
  check(rolled === 0, 'caddy: --rollback вернул 0', outputOf(rollbackCtx).slice(-800))
  check(
    sameSnapshot(original, await snapshot(rollbackCtx, paths)),
    'caddy: --rollback вернул Caddyfile как до fix',
  )
  const afterRollbackValidate = await direct(rollbackCtx, 'caddy', [
    'validate',
    '--config',
    CADDYFILE_PATH,
    '--adapter',
    'caddyfile',
  ])
  check(afterRollbackValidate.ok, 'caddy validate после отката успешен', afterRollbackValidate.text)
  await waitFor('caddy: HSTS исчез после отката', () => {
    const response = probeHeaders(CADDY_HTTPS_PORT)
    return response !== null && !hasHeader(response.headers, 'strict-transport-security')
  })
  check(
    !hasHeader(httpHeaders(CADDY_HTTPS_PORT).headers, 'strict-transport-security'),
    'caddy: после отката HSTS снова нет',
  )

  // Отрицательный случай: настоящий caddy validate с битой копией Caddyfile
  const negative = createStandCtx({
    container,
    tempDir,
    now: new Date('2026-11-07T13:00:00.000Z'),
  })
  negative.setValidatorHook(async () => {
    const actual = await negative.read(CADDYFILE_PATH)
    const broken = '/tmp/stand-Caddyfile.broken'
    // Незакрытый блок: заведомо битый синтаксис, который настоящий caddy отвергнет
    await negative.write(broken, `${actual ?? ''}\nbroken-stand.invalid {\n    respond "ok"\n`)
    try {
      return await negative.execRaw('caddy', [
        'validate',
        '--config',
        broken,
        '--adapter',
        'caddyfile',
      ])
    } finally {
      await negative.remove(broken)
    }
  })
  const negativeCode = await runFixOn(negative, ['caddy'])
  check(negativeCode === 1, 'caddy: битый конфиг даёт код 1', outputOf(negative).slice(-800))
  check(
    sameSnapshot(original, await snapshot(negative, paths)),
    'caddy: при провале валидации Caddyfile откатился',
  )
  const negativeValidate = await direct(negative, 'caddy', [
    'validate',
    '--config',
    CADDYFILE_PATH,
    '--adapter',
    'caddyfile',
  ])
  check(negativeValidate.ok, 'caddy validate после отрицательного случая успешен', negativeValidate.text)
  check(
    outputOf(negative).includes('вернул файлы из бэкапа'),
    'caddy: в выводе есть сообщение об откате',
  )
}

function fixtureConfigs(): string[] {
  const dir = join(import.meta.dir, '..', 'fixtures')
  const found: string[] = []
  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.json')) continue
    const text = readFileSync(join(dir, name), 'utf8')
    if (text.includes('# configuration file ') || text.includes('Caddyfile')) found.push(name)
  }
  return found
}

async function main(): Promise<void> {
  console.log(`стенд: реальные nginx ${NGINX_IMAGE} и caddy ${CADDY_IMAGE}`)
  console.log(`данные: ${STAND_ROOT}`)
  ensureImage(NGINX_IMAGE)
  ensureImage(CADDY_IMAGE)
  startNetwork()

  try {
    await runNginx()
    await runCaddy()
    const fixtures = fixtureConfigs()
    console.log(
      fixtures.length === 0
        ? '\nфикстур с nginx -T или Caddyfile в tests/fixtures нет — дополнительных случаев нет'
        : `\nфикстуры с конфигами: ${fixtures.join(', ')}`,
    )
  } finally {
    cleanup()
  }
  console.log(`\nстенд пройден: ${String(checksPassed)} проверок зелёные`)
}

try {
  await main()
} catch (error) {
  console.error(`\n${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
} finally {
  cleanup()
}
