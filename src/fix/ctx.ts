import { chmod, chown, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises'
import { createInterface } from 'node:readline/promises'
import { platform } from 'node:os'
import { runCommand } from '../exec'
import type { FixCtx, FileInfo } from './types'

async function readText(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf8')
  } catch {
    return null
  }
}

async function fileInfo(path: string): Promise<FileInfo | null> {
  try {
    const info = await stat(path)
    return { mode: info.mode & 0o777, uid: info.uid, gid: info.gid }
  } catch {
    return null
  }
}

async function exists(path: string): Promise<boolean> {
  return (await fileInfo(path)) !== null
}

async function ask(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  try {
    const answer = (await rl.question(question)).trim().toLowerCase()
    return answer === 'y' || answer === 'yes' || answer === 'д' || answer === 'да'
  } finally {
    rl.close()
  }
}

/** Настоящий контекст: файлы, команды, stdin и часы сервера */
export function createFixCtx(): FixCtx {
  return {
    platform: platform(),
    uid: typeof process.getuid === 'function' ? process.getuid() : null,
    now: new Date(),
    run: (cmd, args = []) => runCommand(cmd, args),
    read: readText,
    write: async (path, content) => {
      await writeFile(path, content, 'utf8')
    },
    rename: async (from, to) => {
      await rename(from, to)
    },
    mkdir: async (path, mode) => {
      await mkdir(path, { recursive: true, mode })
    },
    exists,
    remove: async (path) => {
      await rm(path, { force: true })
    },
    stat: fileInfo,
    chmod: async (path, mode) => {
      await chmod(path, mode)
    },
    chown: async (path, uid, gid) => {
      await chown(path, uid, gid)
    },
    confirm: ask,
    stdinIsTTY: process.stdin.isTTY,
    out: (text) => {
      process.stdout.write(text)
    },
    err: (text) => {
      process.stderr.write(text)
    },
    sleep: (ms) =>
      new Promise((resolve) => {
        setTimeout(resolve, ms)
      }),
  }
}
