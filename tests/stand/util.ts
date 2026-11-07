import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { ExecErr, ExecResult } from '../../src/types'
import type { FileInfo, FixCtx } from '../../src/fix/types'

/** Всё, что стенд пишет на диск, живёт только здесь */
export const STAND_ROOT = '/Volumes/Storage/Caches/borodatych-security-stand'
export const NGINX_IMAGE = 'nginx:1.27.3-alpine'
export const CADDY_IMAGE = 'caddy:2.8.4-alpine'

export interface ShellResult {
  ok: boolean
  code: number
  stdout: string
  stderr: string
}

/** Запуск команды без shell: аргументы не переинтерпретируются */
export function sh(cmd: readonly string[], cwd?: string): ShellResult {
  const proc = Bun.spawnSync({
    cmd: [...cmd],
    stdout: 'pipe',
    stderr: 'pipe',
    ...(cwd === undefined ? {} : { cwd }),
  })
  return {
    ok: proc.exitCode === 0,
    code: proc.exitCode,
    stdout: proc.stdout.toString(),
    stderr: proc.stderr.toString(),
  }
}

export function must(cmd: readonly string[], what: string): ShellResult {
  const result = sh(cmd)
  if (!result.ok) {
    throw new Error(`${what}: код ${String(result.code)}\n${result.stderr.trim()}`)
  }
  return result
}

export function prepareRunDir(name: string): string {
  const dir = join(STAND_ROOT, 'run', name)
  rmSync(dir, { recursive: true, force: true })
  mkdirSync(dir, { recursive: true })
  return dir
}

let tempCounter = 0

/** Временный файл на хосте: его копирует docker cp внутрь контейнера */
function tempFile(dir: string, content: string): string {
  tempCounter += 1
  const path = join(dir, `tmp-${process.pid}-${String(tempCounter)}`)
  writeFileSync(path, content, 'utf8')
  return path
}

function parseMode(text: string): FileInfo | null {
  const parts = text.trim().split(/\s+/)
  if (parts.length !== 3) return null
  const mode = Number.parseInt(parts[0] ?? '', 8)
  const uid = Number.parseInt(parts[1] ?? '', 10)
  const gid = Number.parseInt(parts[2] ?? '', 10)
  if (Number.isNaN(mode) || Number.isNaN(uid) || Number.isNaN(gid)) return null
  return { mode, uid, gid }
}

function reasonFor(result: ShellResult): ExecErr['reason'] {
  if (result.code === 127 || /not found|executable file not found/i.test(result.stderr)) {
    return 'missing'
  }
  if (/permission denied|operation not permitted/i.test(result.stderr)) return 'denied'
  return 'error'
}

/** Проверка, которую стенд подменяет для отрицательного случая */
export type ValidatorHook = (cmd: string, args: readonly string[]) => Promise<ExecResult>

export interface StandCtx extends FixCtx {
  outText: string[]
  errText: string[]
  /** Настоящая команда в контейнере, мимо подмены валидатора */
  execRaw: (cmd: string, args?: readonly string[]) => Promise<ExecResult>
  setValidatorHook: (hook: ValidatorHook | null) => void
}

export interface StandCtxOptions {
  container: string
  tempDir: string
  now: Date
}

/**
 * FixCtx, у которого файлы и команды уходят в контейнер через docker exec/cp.
 * Снаружи остаются только часы, подтверждение и вывод.
 */
export function createStandCtx(options: StandCtxOptions): StandCtx {
  const { container, tempDir, now } = options
  const outText: string[] = []
  const errText: string[] = []
  let validatorHook: ValidatorHook | null = null

  const exec = (cmd: string, args: readonly string[]): ExecResult => {
    const result = sh(['docker', 'exec', container, cmd, ...args])
    if (result.ok) {
      return { ok: true, stdout: result.stdout, stderr: result.stderr, code: 0 }
    }
    return {
      ok: false,
      reason: reasonFor(result),
      stdout: result.stdout,
      stderr: result.stderr,
      code: result.code,
    }
  }

  const mustExec = (cmd: string, args: readonly string[]): void => {
    const result = exec(cmd, args)
    if (!result.ok) throw new Error(`${cmd}: ${result.stderr.trim() || result.stdout.trim()}`)
  }

  const isValidation = (cmd: string, args: readonly string[]): boolean =>
    (cmd === 'nginx' && args[0] === '-t') || (cmd === 'caddy' && args[0] === 'validate')

  return {
    platform: 'linux',
    uid: 0,
    now,
    outText,
    errText,
    run: (cmd, args = []) => {
      if (validatorHook !== null && isValidation(cmd, args)) {
        return validatorHook(cmd, args)
      }
      return Promise.resolve(exec(cmd, args))
    },
    read: (path) => {
      const result = sh(['docker', 'exec', container, 'cat', path])
      return Promise.resolve(result.ok ? result.stdout : null)
    },
    write: (path, content) => {
      const host = tempFile(tempDir, content)
      try {
        const result = sh(['docker', 'cp', host, `${container}:${path}`])
        if (!result.ok) throw new Error(`docker cp ${path}: ${result.stderr.trim()}`)
      } finally {
        rmSync(host, { force: true })
      }
      return Promise.resolve()
    },
    rename: (from, to) => {
      mustExec('mv', ['-f', from, to])
      return Promise.resolve()
    },
    mkdir: (path, mode) => {
      mustExec('mkdir', ['-p', '-m', mode.toString(8), path])
      return Promise.resolve()
    },
    exists: (path) => Promise.resolve(exec('test', ['-e', path]).ok),
    remove: (path) => {
      mustExec('rm', ['-f', path])
      return Promise.resolve()
    },
    stat: (path) => {
      const result = exec('stat', ['-c', '%a %u %g', path])
      return Promise.resolve(result.ok ? parseMode(result.stdout) : null)
    },
    chmod: (path, mode) => {
      mustExec('chmod', [mode.toString(8), path])
      return Promise.resolve()
    },
    chown: (path, uid, gid) => {
      mustExec('chown', [`${String(uid)}:${String(gid)}`, path])
      return Promise.resolve()
    },
    confirm: () => Promise.resolve(true),
    stdinIsTTY: true,
    out: (text) => {
      outText.push(text)
    },
    err: (text) => {
      errText.push(text)
    },
    sleep: () => Promise.resolve(),
    execRaw: (cmd, args = []) => Promise.resolve(exec(cmd, args)),
    setValidatorHook: (hook) => {
      validatorHook = hook
    },
  }
}

export interface HttpHeaders {
  status: number
  headers: Map<string, string>
}

function parseHeaders(raw: string): Map<string, string> {
  const headers = new Map<string, string>()
  for (const line of raw.split(/\r?\n/)) {
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    const name = line.slice(0, colon).trim().toLowerCase()
    const value = line.slice(colon + 1).trim()
    headers.set(name, value)
  }
  return headers
}

function curlHeaderArgs(port: number, path: string, extra: readonly string[]): string[] {
  const url = `https://stand.test:${String(port)}${path}`
  return [
    'curl',
    '-sk',
    '--max-time',
    '15',
    '--resolve',
    `stand.test:${String(port)}:127.0.0.1`,
    '-D',
    '-',
    '-o',
    '/dev/null',
    ...extra,
    url,
  ]
}

function parseCurlHeaders(raw: string): HttpHeaders {
  const blocks = raw.split(/\r?\n\r?\n/).filter((block) => block.trim().length > 0)
  const last = blocks[blocks.length - 1] ?? ''
  const lines = last.split(/\r?\n/)
  const statusLine = lines[0] ?? ''
  const match = /^HTTP\/\S+\s+(\d+)/.exec(statusLine)
  const status = match === null ? 0 : Number.parseInt(match[1] ?? '0', 10)
  return { status, headers: parseHeaders(lines.slice(1).join('\n')) }
}

/** Мягкая проверка: во время старта контейнера curl может ещё не соединиться */
export function probeHeaders(port: number, path = '/'): HttpHeaders | null {
  const result = sh(curlHeaderArgs(port, path, []))
  return result.ok ? parseCurlHeaders(result.stdout) : null
}

/** Запрос к стенду с подменой DNS: curl сам смотрит на 127.0.0.1 */
export function httpHeaders(port: number, path = '/', extra: readonly string[] = []): HttpHeaders {
  const result = must(curlHeaderArgs(port, path, extra), `curl https://stand.test:${String(port)}${path}`)
  return parseCurlHeaders(result.stdout)
}

/** HTTP без TLS: порт на хосте и необязательный Host */
export function httpStatus(args: {
  url: string
  host?: string
  path?: string
}): number {
  const extra = args.host === undefined ? [] : ['-H', `Host: ${args.host}`]
  const result = must(
    [
      'curl',
      '-s',
      '--max-time',
      '15',
      '-o',
      '/dev/null',
      '-w',
      '%{http_code}',
      ...extra,
      `${args.url}${args.path ?? '/'}`,
    ],
    `curl ${args.url}`,
  )
  return Number.parseInt(result.stdout.trim(), 10) || 0
}

/** Быстрые запросы подряд: сколько ответов 429/503 */
export function burstStatuses(port: number, count: number): number[] {
  const statuses: number[] = []
  for (let index = 0; index < count; index += 1) {
    statuses.push(httpHeaders(port).status)
  }
  return statuses
}

export function hasHeader(headers: Map<string, string>, name: string): boolean {
  return headers.has(name.toLowerCase())
}

export function headerValue(headers: Map<string, string>, name: string): string | null {
  return headers.get(name.toLowerCase()) ?? null
}
