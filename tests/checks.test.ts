import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { evaluateSshPolicy } from '../src/checks/base/ssh-auth'
import { systemdSandbox } from '../src/checks/isolation/systemd-sandbox'
import { netFirewall } from '../src/checks/net/firewall'
import { netListen } from '../src/checks/net/listen'
import { opsBackup } from '../src/checks/ops/backup'
import type { SshPolicy } from '../src/parsers/system'
import type { Ctx, ExecResult, Status } from '../src/types'

function fixture(name: string): Record<string, string> {
  const path = join(import.meta.dir, 'fixtures', name)
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, string>
}

const ss = fixture('ss.json')
const sshd = fixture('sshd.json')
const systemd = fixture('systemd.json')
const misc = fixture('misc.json')

const missing = (): ExecResult => ({
  ok: false,
  reason: 'missing',
  stdout: '',
  stderr: '',
  code: null,
})
const ok = (stdout: string): ExecResult => ({ ok: true, stdout, stderr: '', code: 0 })

const NOW = new Date('2026-11-06T12:00:00Z')

interface FakeOptions {
  commands?: Record<string, ExecResult>
  files?: Record<string, string>
  dirs?: Record<string, string[]>
}

function fakeCtx(options: FakeOptions = {}): Ctx {
  return {
    platform: 'linux',
    now: NOW,
    env: {},
    run: (cmd, args = []) => Promise.resolve(options.commands?.[`${cmd} ${args.join(' ')}`] ?? missing()),
    read: (path) => Promise.resolve(options.files?.[path] ?? null),
    readdir: (path) => Promise.resolve(options.dirs?.[path] ?? null),
    statMtime: () => Promise.resolve(null),
  }
}

describe('ssh.auth: все комбинации', () => {
  interface Combo {
    passwords: boolean | null
    kbd: boolean | null
    root: string | null
    expected: Status
  }

  const combos: Combo[] = [
    { passwords: false, kbd: false, root: 'no', expected: 'ok' },
    { passwords: false, kbd: false, root: 'prohibit-password', expected: 'ok' },
    { passwords: false, kbd: false, root: 'without-password', expected: 'ok' },
    { passwords: false, kbd: false, root: null, expected: 'ok' },
    { passwords: false, kbd: false, root: 'yes', expected: 'warn' },
    { passwords: true, kbd: false, root: 'no', expected: 'fail' },
    { passwords: false, kbd: true, root: 'no', expected: 'fail' },
    { passwords: true, kbd: true, root: 'yes', expected: 'fail' },
    { passwords: false, kbd: false, root: 'yes', expected: 'warn' },
    { passwords: null, kbd: false, root: 'no', expected: 'warn' },
  ]

  for (const combo of combos) {
    test(`passwords=${String(combo.passwords)} kbd=${String(combo.kbd)} root=${String(combo.root)} → ${combo.expected}`, () => {
      const policy: SshPolicy = {
        passwordAuthentication: combo.passwords,
        kbdInteractiveAuthentication: combo.kbd,
        permitRootLogin: combo.root,
        pubkeyAuthentication: true,
      }
      expect(evaluateSshPolicy(policy).status).toBe(combo.expected)
    })
  }

  test('root по ключу — warn, но не дырка', () => {
    const result = evaluateSshPolicy({
      passwordAuthentication: false,
      kbdInteractiveAuthentication: false,
      permitRootLogin: 'yes',
      pubkeyAuthentication: true,
    })
    expect(result.findings.join(' ')).toContain('permitrootlogin yes')
    expect(result.status).toBe('warn')
  })

  test('фикстура «только ключи» — ok', () => {
    const result = evaluateSshPolicy({
      passwordAuthentication: false,
      kbdInteractiveAuthentication: false,
      permitRootLogin: 'prohibit-password',
      pubkeyAuthentication: true,
    })
    expect(result.status).toBe('ok')
    expect(sshd.keysOnly).toContain('passwordauthentication no')
  })
})

describe('net.firewall: без экрана, но только 22/80/443', () => {
  test('только разрешённые порты — warn, второй слой', async () => {
    const ctx = fakeCtx({
      commands: { 'ss -ltnup': ok(ss.baseAllowedOnly ?? '') },
    })
    const result = await netFirewall.run(ctx)
    expect(result.status).toBe('warn')
    expect(result.findings.join(' ')).toContain('только 22, 80 и 443')
  })

  test('лишний порт без экрана — fail', async () => {
    const ctx = fakeCtx({ commands: { 'ss -ltnup': ok(ss.ltnup ?? '') } })
    const result = await netFirewall.run(ctx)
    expect(result.status).toBe('fail')
    expect(result.findings.join(' ')).toContain('0.0.0.0:6379')
  })

  test('ss читается один раз на net.listen и net.firewall', async () => {
    let calls = 0
    const ctx: Ctx = {
      platform: 'linux',
      now: NOW,
      env: {},
      run: (cmd) => {
        if (cmd === 'ss') calls += 1
        return Promise.resolve(cmd === 'ss' ? ok(ss.baseAllowedOnly ?? '') : missing())
      },
      read: () => Promise.resolve(null),
      readdir: () => Promise.resolve(null),
      statMtime: () => Promise.resolve(null),
    }
    await netListen.run(ctx)
    await netFirewall.run(ctx)
    expect(calls).toBe(1)
  })

  test('net.listen: база наружу поднимает важность до critical', async () => {
    const ctx = fakeCtx({ commands: { 'ss -ltnup': ok(ss.ltnup ?? '') } })
    const result = await netListen.run(ctx)
    expect(result.status).toBe('fail')
    expect(result.severity).toBe('critical')
  })
})

describe('systemd.sandbox: только службы, слушающие порты', () => {
  test('cron и ssh не оцениваются, чужие юниты отфильтрованы', async () => {
    const units: Record<number, string> = {
      812: 'ssh.service',
      901: 'caddy.service',
      1002: 'postgresql.service',
      1100: 'node-app.service',
      1200: 'redis.service',
      640: 'avahi-daemon.service',
    }
    let analyzeArgs: readonly string[] = []
    const ctx: Ctx = {
      platform: 'linux',
      now: NOW,
      env: {},
      run: (cmd, args = []) => {
        if (cmd === 'ss') return Promise.resolve(ok(ss.ltnup ?? ''))
        if (cmd === 'systemd-analyze') {
          analyzeArgs = args
          return Promise.resolve(ok(systemd.analyzeSecurity ?? ''))
        }
        return Promise.resolve(missing())
      },
      read: (path) => {
        const match = /^\/proc\/(\d+)\/cgroup$/.exec(path)
        const pid = match === null ? undefined : Number(match[1])
        if (pid === undefined) return Promise.resolve(null)
        const unit = units[pid]
        return Promise.resolve(unit === undefined ? null : `0::/system.slice/${unit}\n`)
      },
      readdir: () => Promise.resolve(null),
      statMtime: () => Promise.resolve(null),
    }

    const result = await systemdSandbox.run(ctx)
    expect(result.status).toBe('warn')
    expect(result.findings).toContain('ssh не оценивается: его высокая оценка — норма')
    expect(result.findings.join(' ')).toContain('postgresql.service: оценка 8.1')
    expect(result.findings.join(' ')).not.toContain('cron.service')
    expect(analyzeArgs).toContain('caddy.service')
    expect(analyzeArgs).not.toContain('ssh.service')
    expect(analyzeArgs).not.toContain('cron.service')
  })
})

describe('ops.backup: таймеры и cron', () => {
  test('таймер с командой-скриптом — warn «проверьте руками»', async () => {
    const ctx = fakeCtx({
      commands: {
        'systemctl list-timers --all --no-pager': ok(systemd.timers ?? ''),
        'systemctl cat backup.service': ok('ExecStart=/srv/vibememory/bin/hostBackup.sh\n'),
      },
    })
    const result = await opsBackup.run(ctx)
    expect(result.status).toBe('warn')
    expect(result.findings.join(' ')).toContain('hostBackup.sh')
    expect(result.findings.join(' ')).toContain('проверьте руками')
  })

  test('cron: локальный pg_dump — fail, rclone наружу — ok', async () => {
    const ctx = fakeCtx({
      commands: { 'crontab -l': ok(misc.backupConfig ?? '') },
    })
    const result = await opsBackup.run(ctx)
    expect(result.status).toBe('fail')
    expect(result.findings.join(' ')).toContain('только локально')
    expect(result.findings.join(' ')).toContain('пишет наружу')
  })

  test('только локальный restic — fail', async () => {
    const ctx = fakeCtx({ commands: { 'crontab -l': ok(misc.backupLocalOnly ?? '') } })
    const result = await opsBackup.run(ctx)
    expect(result.status).toBe('fail')
    expect(result.findings.join(' ')).toContain('только локально')
  })

  test('только удалённый rclone — ok с фактом', async () => {
    const ctx = fakeCtx({
      commands: { 'crontab -l': ok('15 3 * * * rclone sync /srv/app remote:backup/app\n') },
    })
    const result = await opsBackup.run(ctx)
    expect(result.status).toBe('ok')
    expect(result.findings.join(' ')).toContain('восстановление не проверено')
  })
})
