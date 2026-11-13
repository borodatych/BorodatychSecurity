import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { BUN_SUPPORT, NODE_SUPPORT, PHP_SUPPORT } from '../src/data/runtimes'
import { parseDockerInspect, parseDockerPsPorts } from '../src/parsers/docker'
import {
  daysBetween,
  evaluateEol,
  evaluateOsSupport,
  parseOsRelease,
  parseVersion,
  runtimeKey,
} from '../src/parsers/os'
import {
  isWildcardAddress,
  parseAptSimulateSecurity,
  parseAutoUpgrades,
  parseBackupConfig,
  parseCscliBouncersJson,
  parseStatMode,
  parseCscliCapiStatus,
  parseFail2banChain,
  parseFail2banStatus,
  parseIptablesPolicy,
  parseProStatus,
  parseSshdConfig,
  parseSsListen,
  parseSystemdAnalyzeSecurity,
  parseUfwStatus,
  redactSecrets,
  sshPolicy,
} from '../src/parsers/system'

function fixture(name: string): Record<string, string> {
  const path = join(import.meta.dir, 'fixtures', name)
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, string>
}

const sshd = fixture('sshd.json')
const ss = fixture('ss.json')
const docker = fixture('docker.json')
const systemd = fixture('systemd.json')
const fail2ban = fixture('fail2ban.json')
const osRelease = fixture('os-release.json')
const apt = fixture('apt.json')
const misc = fixture('misc.json')

const NOW = new Date('2026-11-06T12:00:00Z')

describe('os-release и сроки поддержки', () => {
  test('разбор ключей и кавычек', () => {
    const release = parseOsRelease(osRelease.ubuntu2004 ?? '')
    expect(release.ID).toBe('ubuntu')
    expect(release.VERSION_ID).toBe('20.04')
    expect(release.PRETTY_NAME).toBe('Ubuntu 20.04.6 LTS')
  })

  test('Ubuntu 20.04 истекла', () => {
    const state = evaluateOsSupport(parseOsRelease(osRelease.ubuntu2004 ?? ''), NOW)
    expect(state.key).toBe('ubuntu:20.04')
    expect(state.status).toBe('fail')
    expect(state.daysLeft).toBeLessThan(0)
    expect(state.until).toBe('2025-05-31')
  })

  test('Ubuntu 24.04 и Debian 13 поддерживаются', () => {
    expect(evaluateOsSupport(parseOsRelease(osRelease.ubuntu2404 ?? ''), NOW).status).toBe('ok')
    expect(evaluateOsSupport(parseOsRelease(osRelease.debian13 ?? ''), NOW).status).toBe('ok')
  })

  test('неизвестная ОС — unknown', () => {
    const state = evaluateOsSupport({ ID: 'alpine', VERSION_ID: '3.20' }, NOW)
    expect(state.known).toBe(false)
    expect(state.status).toBe('unknown')
  })

  test('дни и warn за 90 дней', () => {
    expect(daysBetween(NOW, new Date('2026-11-16T12:00:00Z'))).toBe(10)
    const table = { 'x:1': { until: '2026-12-01' } }
    expect(evaluateEol(table, 'x:1', NOW).status).toBe('warn')
  })

  test('версии и ключи таблиц', () => {
    expect(parseVersion('v24.18.0')).toEqual({ major: 24, minor: 18, patch: 0 })
    expect(parseVersion('PHP 8.3.2 (cli)')).toEqual({ major: 8, minor: 3, patch: 2 })
    expect(parseVersion('psql (PostgreSQL) 16.3')).toEqual({ major: 16, minor: 3, patch: 0 })
    expect(parseVersion('unknown')).toBeNull()
    expect(runtimeKey(NODE_SUPPORT.versions, { major: 24, minor: 18, patch: 0 }, 'major')).toBe('24')
    expect(runtimeKey(PHP_SUPPORT.versions, { major: 8, minor: 3, patch: 2 }, 'minor')).toBe('8.3')
    expect(runtimeKey(BUN_SUPPORT.versions, { major: 9, minor: 0, patch: 0 }, 'minor')).toBeNull()
  })
})

describe('sshd', () => {
  test('пароли и root разрешены', () => {
    const policy = sshPolicy(parseSshdConfig(sshd.withPasswords ?? ''))
    expect(policy.passwordAuthentication).toBe(true)
    expect(policy.permitRootLogin).toBe('yes')
    expect(policy.kbdInteractiveAuthentication).toBe(true)
    expect(policy.pubkeyAuthentication).toBe(true)
  })

  test('только ключи', () => {
    const config = parseSshdConfig(sshd.keysOnly ?? '')
    const policy = sshPolicy(config)
    expect(policy.passwordAuthentication).toBe(false)
    expect(policy.permitRootLogin).toBe('prohibit-password')
    expect(policy.kbdInteractiveAuthentication).toBe(false)
    expect(policy.pubkeyAuthentication).toBe(true)
  })

  test('первое значение ключа побеждает, комментарии пропускаются', () => {
    const config = parseSshdConfig('# comment\nPasswordAuthentication no\nPasswordAuthentication yes\n')
    expect(config.passwordauthentication).toBe('no')
  })
})

describe('ss -ltnup', () => {
  test('база на 0.0.0.0 и 127.0.0.1', () => {
    const entries = parseSsListen(ss.ltnup ?? '')
    expect(entries.length).toBe(9)
    const ssh = entries.find((entry) => entry.port === 22 && entry.address === '0.0.0.0')
    expect(ssh?.process).toBe('sshd')
    const local = entries.find((entry) => entry.port === 5432 && entry.address === '127.0.0.1')
    expect(local?.process).toBe('postgres')
    expect(entries.find((entry) => entry.port === 6379)?.address).toBe('0.0.0.0')
    expect(entries.find((entry) => entry.proto === 'udp')?.port).toBe(5353)
    expect(entries.some((entry) => entry.address === '::' && entry.port === 22)).toBe(true)
  })

  test('только локальные порты', () => {
    const entries = parseSsListen(ss.baseAllowedOnly ?? '')
    expect(entries.length).toBe(4)
    expect(entries.filter((entry) => isWildcardAddress(entry.address)).map((entry) => entry.port)).toEqual([
      22, 443,
    ])
  })

  test('wildcard-адреса', () => {
    expect(isWildcardAddress('0.0.0.0')).toBe(true)
    expect(isWildcardAddress('::')).toBe(true)
    expect(isWildcardAddress('*')).toBe(true)
    expect(isWildcardAddress('127.0.0.1')).toBe(false)
  })
})

describe('docker', () => {
  test('privileged, root и монтирование', () => {
    const containers = parseDockerInspect(docker.privileged ?? '')
    expect(containers.length).toBe(1)
    expect(containers[0]?.name).toBe('web')
    expect(containers[0]?.privileged).toBe(true)
    expect(containers[0]?.capAdd).toEqual(['SYS_ADMIN'])
    expect(containers[0]?.mounts[0]?.source).toBe('/srv/app')
  })

  test('docker.sock и /etc в контейнерах', () => {
    const containers = parseDockerInspect(docker.sock ?? '')
    expect(containers.length).toBe(2)
    const traefik = containers.find((container) => container.name === 'traefik')
    expect(traefik?.mounts.some((mount) => mount.source === '/var/run/docker.sock')).toBe(true)
    const app = containers.find((container) => container.name === 'app')
    expect(app?.mounts.some((mount) => mount.source === '/etc')).toBe(true)
  })

  test('битый JSON не роняет разбор', () => {
    expect(parseDockerInspect('not json')).toEqual([])
  })

  test('порты docker ps', () => {
    const entries = parseDockerPsPorts(docker.psPorts ?? '')
    expect(entries.length).toBe(4)
    const web = entries.find((entry) => entry.name === 'web')
    expect(web?.ports[0]).toEqual({
      hostIp: '0.0.0.0',
      hostPort: 5432,
      containerPort: 5432,
      proto: 'tcp',
    })
    expect(web?.ports[1]?.hostIp).toBe('::')
    expect(entries.find((entry) => entry.name === 'app')?.ports[0]?.hostIp).toBe('127.0.0.1')
    expect(entries.find((entry) => entry.name === 'nginx-proxy-manager')?.ports[0]?.hostPort).toBe(81)
    expect(entries.find((entry) => entry.name === 'solo')?.ports).toEqual([])
  })
})

describe('systemd-analyze security', () => {
  test('строки Overall exposure level', () => {
    const exposures = parseSystemdAnalyzeSecurity(systemd.analyzeSecurity ?? '')
    expect(exposures.length).toBe(4)
    expect(exposures[0]).toEqual({ unit: 'ssh.service', score: '9.6' })
    expect(exposures.filter((item) => Number(item.score) > 7).map((item) => item.unit)).toEqual([
      'ssh.service',
      'postgresql.service',
    ])
  })

  test('табличный вывод', () => {
    const exposures = parseSystemdAnalyzeSecurity(systemd.table ?? '')
    expect(exposures.length).toBe(3)
    expect(exposures[1]).toEqual({ unit: 'caddy.service', score: '6.2' })
  })
})

describe('fail2ban', () => {
  test('список джейлов', () => {
    expect(parseFail2banStatus(fail2ban.status ?? '')).toEqual({
      jails: ['sshd', 'nginx-http-auth'],
      jail: null,
    })
    expect(parseFail2banStatus(fail2ban.statusNoSshd ?? '').jails).toEqual(['nginx-http-auth'])
  })

  test('статус одного джейла', () => {
    expect(parseFail2banStatus(fail2ban.statusSshd ?? '').jail).toBe('sshd')
  })

  test('цепочка и banaction', () => {
    expect(parseFail2banChain(fail2ban.jailLocal ?? '')).toEqual({
      chain: null,
      banaction: 'iptables-multiport',
    })
    expect(parseFail2banChain(fail2ban.jailDockerUser ?? '').chain).toBe('DOCKER-USER')
  })
})

describe('firewall, pro, apt, crowdsec, backup', () => {
  test('ufw', () => {
    expect(parseUfwStatus(misc.ufwActive ?? '')).toBe('active')
    expect(parseUfwStatus(misc.ufwInactive ?? '')).toBe('inactive')
    expect(parseUfwStatus('что-то')).toBe('unknown')
  })

  test('iptables', () => {
    const state = parseIptablesPolicy(misc.iptables ?? '')
    expect(state.rules).toBe(2)
    expect(state.policies.INPUT).toBe('ACCEPT')
    expect(state.policies.FORWARD).toBe('DROP')
    expect(parseIptablesPolicy(misc.iptablesEmpty ?? '').policies.INPUT).toBe('ACCEPT')
  })

  test('pro status', () => {
    expect(parseProStatus(misc.proStatus ?? '')).toEqual({ attached: true, livepatch: true })
    expect(parseProStatus(misc.proNotAttached ?? '').attached).toBe(false)
  })

  test('apt: security-обновления и автообновления', () => {
    expect(parseAptSimulateSecurity(apt.simulate ?? '')).toBe(2)
    expect(parseAutoUpgrades(apt.autoUpgradesOn ?? '')).toEqual({
      unattended: true,
      updateLists: true,
    })
    expect(parseAutoUpgrades(apt.autoUpgradesOff ?? '')).toEqual({
      unattended: false,
      updateLists: false,
    })
  })

  test('crowdsec', () => {
    expect(parseCscliBouncersJson(misc.cscliBouncersJson ?? '')).toEqual([
      { name: 'cs-firewall-bouncer', valid: true, lastPull: new Date('2026-11-06T11:59:30Z') },
      { name: 'old-nginx', valid: true, lastPull: null },
      { name: 'revoked', valid: false, lastPull: new Date('2026-11-06T11:00:00Z') },
    ])
    expect(parseCscliBouncersJson('null\n')).toEqual([])
    expect(parseCscliBouncersJson('')).toEqual([])
    expect(parseCscliBouncersJson('╭── таблица')).toBeNull()
    expect(parseCscliCapiStatus(misc.cscliCapiOn ?? '')).toBe(true)
    expect(parseCscliCapiStatus(misc.cscliCapiOff ?? '')).toBe(false)
  })

  test('stat прав и владельца', () => {
    expect(parseStatMode('600 root:root\n')).toEqual({ mode: '600', owner: 'root:root' })
    expect(parseStatMode('644 www-data:www-data')).toEqual({ mode: '644', owner: 'www-data:www-data' })
    expect(parseStatMode('stat: cannot stat')).toBeNull()
  })

  test('бэкапы и удалённые адреса', () => {
    const jobs = parseBackupConfig(misc.backupConfig ?? '')
    expect(jobs.length).toBe(2)
    expect(jobs[0]?.remote).toBe(false)
    expect(jobs[1]?.remote).toBe(true)
    const local = parseBackupConfig(misc.backupLocalOnly ?? '')
    expect(local.length).toBe(1)
    expect(local[0]?.remote).toBe(false)
    expect(parseBackupConfig(misc.backupNone ?? '')).toEqual([])
  })

  test('секреты вырезаются', () => {
    const redacted = redactSecrets(misc.fakeSecretEnv ?? '')
    expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(redacted).not.toContain('s3cr3t')
    expect(redacted).toContain('AWS_SECRET_ACCESS_KEY=***')
    expect(redacted).toContain('postgres://app:***@db.internal/app')
  })
})
