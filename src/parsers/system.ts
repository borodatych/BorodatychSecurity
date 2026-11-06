/** Скрыть значения секретов: переменные окружения, пароли в аргументах, учётные данные в URL */
export function redactSecrets(text: string): string {
  return text
    .replace(
      /([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PASS|TOKEN|SECRET|API_KEY|APIKEY|KEY)[A-Za-z0-9_]*\s*=\s*)([^\s"'`]+)/gi,
      '$1***',
    )
    .replace(/(--(?:password|pass|token|secret|api-key)(?:=|\s+))([^\s"'`]+)/gi, '$1***')
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/[^\s/@]+):[^\s/@]+@/gi, '$1:***@')
}

function firstValue(record: Record<string, string>, key: string): string | null {
  return record[key] ?? null
}

function yesNo(value: string | null): boolean | null {
  if (value === null) return null
  const normalized = value.toLowerCase()
  if (['yes', 'true', 'on', '1'].includes(normalized)) return true
  if (['no', 'false', 'off', '0'].includes(normalized)) return false
  return null
}

/** Разбор sshd -T и sshd_config: первое значение ключа побеждает, как в sshd */
export function parseSshdConfig(text: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line.length === 0 || line.startsWith('#')) continue
    const match = /^(\S+)\s+(.+)$/.exec(line)
    if (match === null) continue
    const key = (match[1] ?? '').toLowerCase()
    const value = (match[2] ?? '').trim()
    if (!(key in result)) result[key] = value
  }
  return result
}

export interface SshPolicy {
  passwordAuthentication: boolean | null
  permitRootLogin: string | null
  kbdInteractiveAuthentication: boolean | null
  pubkeyAuthentication: boolean | null
}

export function sshPolicy(record: Record<string, string>): SshPolicy {
  return {
    passwordAuthentication: yesNo(firstValue(record, 'passwordauthentication')),
    permitRootLogin: firstValue(record, 'permitrootlogin'),
    kbdInteractiveAuthentication: yesNo(firstValue(record, 'kbdinteractiveauthentication')),
    pubkeyAuthentication: yesNo(firstValue(record, 'pubkeyauthentication')),
  }
}

export interface ListenEntry {
  proto: 'tcp' | 'udp'
  address: string
  port: number
  process: string | null
  pid: number | null
}

/** Разбор `ss -ltnup` */
export function parseSsListen(text: string): ListenEntry[] {
  const entries: ListenEntry[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!/^(tcp|udp)\s/.test(line)) continue
    const tokens = line.split(/\s+/)
    if (tokens.length < 5) continue
    const local = tokens[4]
    if (local === undefined) continue
    const colon = local.lastIndexOf(':')
    if (colon < 0) continue
    const port = Number(local.slice(colon + 1))
    if (!Number.isInteger(port) || port <= 0) continue
    const address = local
      .slice(0, colon)
      .replace(/^\[/, '')
      .replace(/\]$/, '')
      .replace(/%\S+$/, '')
    const processMatch = /users:\(\("([^"]+)"/.exec(line)
    const pidMatch = /\bpid=(\d+)/.exec(line)
    entries.push({
      proto: tokens[0] === 'udp' ? 'udp' : 'tcp',
      address,
      port,
      process: processMatch?.[1] ?? null,
      pid: pidMatch === null ? null : Number(pidMatch[1]),
    })
  }
  return entries
}

export function isWildcardAddress(address: string): boolean {
  return address === '0.0.0.0' || address === '::' || address === '*' || address === ''
}

export interface ServiceExposure {
  unit: string
  score: string
}

/** Разбор `systemd-analyze security` */
export function parseSystemdAnalyzeSecurity(text: string): ServiceExposure[] {
  const result: ServiceExposure[] = []
  const overall = /Overall exposure level for\s+(\S+):\s*([\d.]+)/g
  let match = overall.exec(text)
  while (match !== null) {
    result.push({ unit: match[1] ?? '', score: match[2] ?? '' })
    match = overall.exec(text)
  }
  if (result.length > 0) return result

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    const row = /^(\S+\.(?:service|socket|timer|mount))\s+([\d]+(?:\.[\d]+)?)\b/.exec(line)
    if (row !== null) result.push({ unit: row[1] ?? '', score: row[2] ?? '' })
  }
  return result
}

export interface Fail2banStatus {
  jails: string[]
  jail: string | null
}

/** Разбор `fail2ban-client status` и `fail2ban-client status <jail>` */
export function parseFail2banStatus(text: string): Fail2banStatus {
  let jails: string[] = []
  const list = /Jail list:\s*(.+)/i.exec(text)
  if (list !== null) {
    jails = (list[1] ?? '')
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0)
  }
  const single = /Status for the jail:\s*(\S+)/i.exec(text)
  const jail = single?.[1] ?? null
  if (jail !== null && !jails.includes(jail)) jails = [...jails, jail]
  return { jails, jail }
}

export type UfwState = 'active' | 'inactive' | 'unknown'

/** Разбор `ufw status` */
export function parseUfwStatus(text: string): UfwState {
  if (/^Status:\s*active/im.test(text)) return 'active'
  if (/^Status:\s*inactive/im.test(text)) return 'inactive'
  return 'unknown'
}

export interface IptablesState {
  policies: Record<string, string>
  rules: number
}

/** Разбор `iptables -S` */
export function parseIptablesPolicy(text: string): IptablesState {
  const policies: Record<string, string> = {}
  let rules = 0
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    const policy = /^-P\s+(\S+)\s+(\S+)/.exec(line)
    if (policy !== null) policies[policy[1] ?? ''] = policy[2] ?? ''
    if (line.startsWith('-A ')) rules += 1
  }
  return { policies, rules }
}

export interface ProStatus {
  attached: boolean
  livepatch: boolean
}

/** Разбор `pro status` */
export function parseProStatus(text: string): ProStatus {
  const notAttached = /not attached|unattached/i.test(text)
  const attached =
    !notAttached && (/^SERVICE\s+ENTITLED/im.test(text) || /attached to an Ubuntu Pro/i.test(text))
  const livepatchRow = /^livepatch\s+(\S+)\s+(\S+)/im.exec(text)
  const livepatch =
    livepatchRow !== null && ['enabled', 'warning'].includes((livepatchRow[2] ?? '').toLowerCase())
  return { attached, livepatch }
}

/** Сколько security-обновлений покажет `apt-get -s upgrade` */
export function parseAptSimulateSecurity(text: string): number {
  let count = 0
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (/^Inst\s/.test(line) && /security/i.test(line)) count += 1
  }
  return count
}

export interface AutoUpgradesState {
  unattended: boolean
  updateLists: boolean
}

/** Разбор /etc/apt/apt.conf.d/20auto-upgrades */
export function parseAutoUpgrades(text: string): AutoUpgradesState {
  const values: Record<string, number> = {}
  const re = /APT::Periodic::([A-Za-z-]+)\s+"?(\d+)"?/g
  let match = re.exec(text)
  while (match !== null) {
    values[(match[1] ?? '').toLowerCase()] = Number(match[2] ?? '0')
    match = re.exec(text)
  }
  return {
    unattended: (values['unattended-upgrade'] ?? 0) > 0,
    updateLists: (values['update-package-lists'] ?? 0) > 0,
  }
}

/** Разбор `cscli bouncers list` */
export function parseCscliBouncers(text: string): string[] {
  if (/no bouncers/i.test(text)) return []
  const names: string[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (
      line.length === 0 ||
      line.startsWith('─') ||
      line.startsWith('-') ||
      line.startsWith('╭') ||
      line.startsWith('├') ||
      line.startsWith('╰')
    ) {
      continue
    }
    const cleaned = line.replace(/[│┃|]/g, ' ').trim()
    if (/^name\b/i.test(cleaned)) continue
    if (!/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(cleaned)) continue
    const name = cleaned.split(/\s+/)[0]
    if (name !== undefined && name.length > 0) names.push(name)
  }
  return names
}

/** Разбор `cscli capi status` */
export function parseCscliCapiStatus(text: string): boolean | null {
  if (/not registered|not enabled|not connected|disabled/i.test(text)) return false
  if (/CAPI/i.test(text) && /(enabled|connected|ok|running|registered)/i.test(text)) return true
  return null
}

export interface Fail2banChain {
  chain: string | null
  banaction: string | null
}

/** Разбор конфигов fail2ban: цепочка и banaction */
export function parseFail2banChain(text: string): Fail2banChain {
  const chain = /^\s*chain\s*=\s*(\S+)/im.exec(text)
  const banaction = /^\s*banaction\s*=\s*(\S+)/im.exec(text)
  return {
    chain: chain?.[1] ?? null,
    banaction: banaction?.[1] ?? null,
  }
}

export interface BackupJob {
  command: string
  remote: boolean
}

const REMOTE_RE =
  /(?:s3:|b2:|gcs:|azure:|sftp:|ssh:|rclone\b.*\b[\w.-]+:|rsync\b.*@|scp\b.*@|borg\b.*::)/i

/** Разбор cron/systemd на задания бэкапа; значения секретов вырезаются */
export function parseBackupConfig(text: string): BackupJob[] {
  const jobs: BackupJob[] = []
  const seen = new Set<string>()
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line.length === 0 || line.startsWith('#')) continue
    if (!/(pg_dump|restic|borg|rclone)/i.test(line)) continue
    const command = redactSecrets(line).slice(0, 200)
    if (seen.has(command)) continue
    seen.add(command)
    jobs.push({ command, remote: REMOTE_RE.test(line) })
  }
  return jobs
}

const BACKUP_RE = /\b(?:backup|dump|restic|borg|rclone|pg_dump|rsync)\b/i

/** Имя таймера, юнита или команда похожа на бэкап */
export function isBackupText(text: string): boolean {
  return BACKUP_RE.test(text)
}

export type BackupTarget = 'remote' | 'local' | 'unknown'

function remoteRepoSpec(value: string): boolean {
  return /^(?:s3:|b2:|gcs:|gs:|azure:|sftp:|ssh:|rest:|rclone:|swift:|http:\/\/|https:\/\/)/i.test(
    value,
  ) || /^(?:[^/\s]+@)?[^/\s:]+:/.test(value)
}

function lastArgument(tokens: readonly string[]): string | null {
  for (let index = tokens.length - 1; index >= 0; index -= 1) {
    const token = tokens[index]
    if (token !== undefined && !token.startsWith('-')) return token
  }
  return null
}

/**
 * Куда пишет команда бэкапа: наружу, только локально или непонятно.
 * Секреты в команду не попадают — вызывающий обязан их вырезать.
 */
export function classifyBackupCommand(command: string): BackupTarget {
  const line = command.trim()
  if (line.length === 0) return 'unknown'
  if (/\bgit\s+push\b/i.test(line)) return 'remote'
  if (/\b(?:aws\s+s3|s3cmd|mc\s+(?:cp|mirror)|gsutil|az\s+storage)\b/i.test(line)) {
    return 'remote'
  }
  if (/\bscp\b/i.test(line) && /@|:/.test(line)) return 'remote'

  if (/\brclone\b/i.test(line)) {
    const tokens = line.split(/\s+/)
    const remote = tokens.find((token) => /^[A-Za-z0-9_.-]+:/.test(token) && !token.startsWith('/'))
    if (remote !== undefined) return 'remote'
    return lastArgument(tokens.slice(tokens.findIndex((token) => /rclone/i.test(token)))) === null
      ? 'unknown'
      : 'local'
  }

  if (/\brestic\b/i.test(line)) {
    const repo = /(?:--repo(?:=|\s+)|-r\s+)(\S+)/.exec(line)?.[1]
    if (repo === undefined) return 'unknown'
    if (remoteRepoSpec(repo)) return 'remote'
    if (/^(?:\/|\.\/|~)/.test(repo)) return 'local'
    return 'unknown'
  }

  if (/\bborg\b/i.test(line)) {
    if (/ssh:\/\/|@[^/\s:]+:/.test(line)) return 'remote'
    if (/(?:^|\s)(?:\/|\.\/|~)\S+/.test(line)) return 'local'
    return 'unknown'
  }

  if (/\brsync\b/i.test(line)) {
    const tokens = line.split(/\s+/)
    const destination = lastArgument(tokens)
    if (destination === null) return 'unknown'
    if (remoteRepoSpec(destination) || /@[^/\s:]+:/.test(destination)) return 'remote'
    if (/^(?:\/|\.\/|~)/.test(destination)) return 'local'
    return 'unknown'
  }

  if (/\bpg_dump\b/i.test(line)) {
    if (/\|\s*(?:ssh|rclone|rsync|s3cmd|aws|gsutil|scp|git)\b/i.test(line)) return 'remote'
    return 'local'
  }

  if (/\b(?:backup|dump)\b/i.test(line)) {
    if (/>\s*\S+/.test(line) || /--(?:file|output|repo)\b/.test(line)) return 'local'
    return 'unknown'
  }

  return 'unknown'
}

export interface SystemdTimer {
  unit: string
  activates: string[]
}

/** Разбор `systemctl list-timers --all --no-pager` */
export function parseSystemdTimers(text: string): SystemdTimer[] {
  const timers: SystemdTimer[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line.length === 0 || /^NEXT\s/.test(line)) continue
    const tokens = line.split(/\s+/)
    const index = tokens.findIndex((token) => token.endsWith('.timer'))
    if (index < 0) continue
    const unit = tokens[index]
    if (unit === undefined) continue
    const activates = tokens
      .slice(index + 1)
      .filter((token) => /\.(?:service|socket|target)$/.test(token))
    timers.push({ unit, activates })
  }
  return timers
}

/** Команды ExecStart из `systemctl cat` */
export function parseExecStart(text: string): string[] {
  const commands: string[] = []
  for (const raw of text.split(/\r?\n/)) {
    const match = /^\s*ExecStart\s*=\s*(.+)$/.exec(raw)
    if (match === null) continue
    const command = (match[1] ?? '').trim().replace(/^[-@+!:]+/, '')
    if (command.length > 0 && !commands.includes(command)) commands.push(command)
  }
  return commands
}

/** Unit= из `systemctl cat <timer>` */
export function parseTimerUnit(text: string): string | null {
  return /^\s*Unit\s*=\s*(\S+)/m.exec(text)?.[1] ?? null
}

/** Имя юнита из содержимого /proc/<pid>/cgroup */
export function unitFromCgroup(text: string): string | null {
  for (const raw of text.split(/\r?\n/)) {
    const match = /\/([^/]+\.(?:service|socket|scope|timer))\s*$/.exec(raw.trim())
    if (match !== null) return match[1] ?? null
  }
  return null
}

/** Имя юнита из вывода `systemctl status <pid>` */
export function unitFromStatus(text: string): string | null {
  const first = /^\s*[●•*]\s+(\S+\.(?:service|socket|scope|timer))/m.exec(text)
  if (first !== null) return first[1] ?? null
  const loaded = /^\s*Loaded:.*?\/([^/\s]+\.(?:service|socket|scope|timer))/m.exec(text)
  return loaded !== null ? (loaded[1] ?? null) : null
}
