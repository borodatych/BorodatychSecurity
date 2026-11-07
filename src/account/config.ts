import { execFileSync } from 'node:child_process'
import {
  chmodSync,
  chownSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { VERSION } from '../version'

/** Адрес сервиса по умолчанию */
export const DEFAULT_API = 'https://security.borodatych.ru'
/** Запись из passwd: дом, uid и gid пользователя */
export interface PasswdEntry {
  home: string
  uid: number
  gid: number
}

export type LookupUser = (name: string) => PasswdEntry | null

/** Откуда брать окружение, uid и пользователя: поля подменяемы в тестах */
export interface AccountEnvOptions {
  env?: NodeJS.ProcessEnv
  uid?: number | null
  lookupUser?: LookupUser
}

export interface TokenOptions extends AccountEnvOptions {
  /** Явный токен: null — токена нет, undefined — читать env и файл */
  token?: string | null
}

function currentUid(): number | null {
  const getuid = process.getuid
  return typeof getuid === 'function' ? getuid() : null
}

const USER_NAME_RE = /^[A-Za-z0-9._-]+$/

/** Дом пользователя по имени; без getent или прав — null */
const defaultLookup: LookupUser = (name) => {
  if (!USER_NAME_RE.test(name)) return null
  try {
    const out = execFileSync('getent', ['passwd', name], { encoding: 'utf8', timeout: 2000 })
    const fields = out.trim().split(':')
    const uid = Number(fields[2])
    const gid = Number(fields[3])
    const home = fields[5] ?? ''
    if (home.length === 0 || !Number.isInteger(uid) || !Number.isInteger(gid)) return null
    return { home, uid, gid }
  } catch {
    return null
  }
}

/** Пользователь, от имени которого запущен sudo; null — запуска не под sudo */
export function sudoUser(options: AccountEnvOptions = {}): string | null {
  const env = options.env ?? process.env
  const uid = options.uid === undefined ? currentUid() : options.uid
  const user = env.SUDO_USER?.trim()
  if (uid !== 0 || user === undefined || user.length === 0) return null
  return user
}

/** Адрес сервиса: BOROSEC_API или значение по умолчанию, без хвостового слэша */
export function apiBase(env: NodeJS.ProcessEnv = process.env): string {
  const value = env.BOROSEC_API?.trim()
  if (value === undefined || value.length === 0) return DEFAULT_API
  return value.replace(/\/+$/, '')
}

function configHome(options: AccountEnvOptions): string {
  const env = options.env ?? process.env
  const user = sudoUser(options)
  if (user !== null) {
    const lookup = options.lookupUser ?? defaultLookup
    const entry = lookup(user)
    // Под sudo root должен увидеть токен обычного пользователя, а не свой
    if (entry !== null) return join(entry.home, '.config')
  }
  const xdg = env.XDG_CONFIG_HOME?.trim()
  if (xdg !== undefined && xdg.length > 0) return xdg
  const home = env.HOME?.trim()
  if (home !== undefined && home.length > 0) return join(home, '.config')
  return join(homedir(), '.config')
}

export function configDir(options: AccountEnvOptions = {}): string {
  return join(configHome(options), 'borodatych-security')
}

export function tokenPath(options: AccountEnvOptions = {}): string {
  return join(configDir(options), 'token')
}

/** Токен: BOROSEC_TOKEN, затем файл; null — не вошли */
export function readToken(options: TokenOptions = {}): string | null {
  if (options.token !== undefined) return options.token
  const env = options.env ?? process.env
  const fromEnv = env.BOROSEC_TOKEN?.trim()
  if (fromEnv !== undefined && fromEnv.length > 0) return fromEnv
  try {
    const value = readFileSync(tokenPath(options), 'utf8').trim()
    return value.length > 0 ? value : null
  } catch {
    return null
  }
}

function safeChown(path: string, entry: PasswdEntry): void {
  try {
    chownSync(path, entry.uid, entry.gid)
  } catch {
    // без прав на смену владельца запись всё равно остаётся у root — не ошибка
  }
}

/** Запись токена атомарно: каталог 700, файл 600, под sudo — владелец SUDO_USER */
export function writeToken(token: string, options: AccountEnvOptions = {}): string {
  const dir = configDir(options)
  const path = tokenPath(options)
  const user = sudoUser(options)
  const entry = user === null ? null : (options.lookupUser ?? defaultLookup)(user)

  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  if (entry !== null) safeChown(dir, entry)

  const tmp = `${path}.${String(process.pid)}.${String(Date.now())}.tmp`
  try {
    writeFileSync(tmp, `${token}\n`, { mode: 0o600 })
    chmodSync(tmp, 0o600)
    if (entry !== null) safeChown(tmp, entry)
    renameSync(tmp, path)
    chmodSync(path, 0o600)
    if (entry !== null) safeChown(path, entry)
  } catch (error) {
    try {
      rmSync(tmp, { force: true })
    } catch {
      // временный файл уже исчез — чистить нечего
    }
    throw error
  }
  return path
}

/** Удалить файл токена; false — файла не было */
export function clearToken(options: AccountEnvOptions = {}): boolean {
  const path = tokenPath(options)
  if (!existsSync(path)) return false
  try {
    rmSync(path, { force: true })
    return true
  } catch {
    return false
  }
}

/** Имя клиента на странице подтверждения; не длиннее 64 знаков */
export function clientName(host: string): string {
  const value = `borodatych-security CLI ${VERSION} на ${host}`
  return value.length > 64 ? value.slice(0, 64) : value
}
