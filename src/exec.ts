import { execFile } from 'node:child_process'
import { readFile, readdir, stat } from 'node:fs/promises'
import { platform } from 'node:os'
import type { Ctx, ExecErr, ExecResult, TlsHandshakeFn } from './types'

/** Единственная точка запуска команд. Всё чтение с таймаутом, shell не используется */
export const EXEC_TIMEOUT_MS = 10_000

const MAX_BUFFER = 4 * 1024 * 1024

const DENIED_RE =
  /permission denied|must be root|are you root|operation not permitted|access denied|not authorized|requires root/i

export function runCommand(
  cmd: string,
  args: readonly string[] = [],
  timeout = EXEC_TIMEOUT_MS,
): Promise<ExecResult> {
  return new Promise((resolve) => {
    try {
      execFile(
        cmd,
        [...args],
        { timeout, maxBuffer: MAX_BUFFER, encoding: 'utf8', shell: false },
        (error, stdout, stderr) => {
        const out = stdout
        const err = stderr

        if (error === null) {
          resolve({ ok: true, stdout: out, stderr: err, code: 0 })
          return
        }

        const e: { code?: unknown; killed?: unknown } = error
        const code = typeof e.code === 'number' ? e.code : null

        let reason: ExecErr['reason'] = 'error'
        if (e.code === 'ENOENT') {
          reason = 'missing'
        } else if (e.code === 'EACCES' || e.code === 'EPERM') {
          reason = 'denied'
        } else if (e.killed === true) {
          reason = 'timeout'
        } else if (DENIED_RE.test(err)) {
          reason = 'denied'
        }

          resolve({ ok: false, reason, stdout: out, stderr: err, code })
        },
      )
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      resolve({ ok: false, reason: 'error', stdout: '', stderr: message, code: null })
    }
  })
}

export async function readText(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf8')
  } catch {
    return null
  }
}

export async function readDir(path: string): Promise<string[] | null> {
  try {
    return await readdir(path)
  } catch {
    return null
  }
}

export async function mtime(path: string): Promise<Date | null> {
  try {
    return (await stat(path)).mtime
  } catch {
    return null
  }
}


export interface CtxOptions {
  now?: Date
  domain?: string
  canaryPaths?: string[]
  env?: NodeJS.ProcessEnv
  runner?: (cmd: string, args: readonly string[]) => Promise<ExecResult>
  fetch?: typeof fetch
  tlsHandshake?: TlsHandshakeFn
}

export function createCtx(options: CtxOptions = {}): Ctx {
  const ctx: Ctx = {
    platform: platform(),
    now: options.now ?? new Date(),
    env: options.env ?? process.env,
    run: (cmd, args = []) =>
      options.runner !== undefined ? options.runner(cmd, args) : runCommand(cmd, args),
    read: readText,
    readdir: readDir,
    statMtime: mtime,
  }
  if (options.domain !== undefined) {
    ctx.domain = options.domain
  }
  if (options.canaryPaths !== undefined) {
    ctx.canaryPaths = options.canaryPaths
  }
  if (options.fetch !== undefined) {
    ctx.fetch = options.fetch
  }
  if (options.tlsHandshake !== undefined) {
    ctx.tlsHandshake = options.tlsHandshake
  }
  return ctx
}
