import type { ExecResult } from '../types'

/** Веб-сервер, который умеем чинить автоматически */
export type FixServer = 'nginx' | 'caddy'

/** Почему пункт не тронули: уже настроено, частично настроено, вне охвата */
export type FixSkipReason =
  | 'already'
  | 'partial'
  | 'unsupported'
  | 'no-conf-d'
  | 'no-block'
  | 'no-server'
  | 'not-covered'

/** Пункт, который остался без правки, с причиной */
export interface FixSkip {
  checkId: string
  target: string
  reason: FixSkipReason
  detail: string
}

/** Правка одного файла: before=null — файл создаём с нуля */
export interface FixEdit {
  path: string
  before: string | null
  after: string
  kind: 'modify' | 'create'
  summary: string
}

/** План починки: что и в каких файлах меняем, что пропускаем */
export interface FixPlan {
  domain: string
  server: FixServer | null
  checks: string[]
  edits: FixEdit[]
  skipped: FixSkip[]
  csp: string | null
}

/** Права и владелец файла, какие были до правки */
export interface FileInfo {
  mode: number
  uid: number
  gid: number
}

/**
 * Внедряемые побочные эффекты: в тестах — запись в память,
 * на сервере — файлы, команды и stdin
 */
export interface FixCtx {
  platform: NodeJS.Platform
  uid: number | null
  now: Date
  run: (cmd: string, args?: readonly string[]) => Promise<ExecResult>
  read: (path: string) => Promise<string | null>
  write: (path: string, content: string) => Promise<void>
  rename: (from: string, to: string) => Promise<void>
  mkdir: (path: string, mode: number) => Promise<void>
  exists: (path: string) => Promise<boolean>
  remove: (path: string) => Promise<void>
  stat: (path: string) => Promise<FileInfo | null>
  chmod: (path: string, mode: number) => Promise<void>
  chown: (path: string, uid: number, gid: number) => Promise<void>
  confirm: (question: string) => Promise<boolean>
  stdinIsTTY: boolean
  out: (text: string) => void
  err: (text: string) => void
  sleep: (ms: number) => Promise<void>
}

/** Запись манифеста бэкапа: по ней работает --rollback */
export interface BackupFile {
  /** Полный путь исходного файла */
  path: string
  /** Путь копии внутри каталога бэкапа, от его корня */
  backup: string
  mode: number | null
  uid: number | null
  gid: number | null
}

export interface BackupManifest {
  version: 1
  createdAt: string
  domain: string
  server: FixServer
  files: BackupFile[]
  /** Файлы, которых до правки не было: при откате их удаляем */
  created: string[]
  rollbackCommand: string
}
