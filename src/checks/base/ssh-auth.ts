import { ru } from '../../i18n/ru'
import { parseSshdConfig, sshPolicy, type SshPolicy } from '../../parsers/system'
import type { Check, CheckResult } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

const ROOT_KEY_ONLY = new Set(['prohibit-password', 'without-password', 'forced-commands-only'])

/**
 * Правила ssh.auth:
 * fail — разрешены пароли или keyboard-interactive;
 * warn — root по ключу (`permitrootlogin yes` при выключенных паролях) или
 *        настройка паролей не найдена;
 * ok — root запрещён (`no`) или только по ключу (`prohibit-password`).
 */
export function evaluateSshPolicy(policy: SshPolicy): CheckResult {
  const findings: string[] = []
  let status: CheckResult['status'] = 'ok'
  const passwords = policy.passwordAuthentication
  const kbd = policy.kbdInteractiveAuthentication
  const root = (policy.permitRootLogin ?? '').toLowerCase()

  if (passwords === true) {
    findings.push(ru.facts.setting('passwordauthentication', 'yes'))
    status = 'fail'
  } else if (passwords === false) {
    findings.push(ru.facts.setting('passwordauthentication', 'no'))
  } else {
    findings.push(ru.facts.setting('passwordauthentication', 'не найден, по умолчанию обычно yes'))
    status = 'warn'
  }

  if (kbd === true) {
    findings.push(ru.facts.setting('kbdinteractiveauthentication', 'yes'))
    status = 'fail'
  } else if (kbd === false) {
    findings.push(ru.facts.setting('kbdinteractiveauthentication', 'no'))
  }

  if (root === 'yes') {
    findings.push(ru.facts.setting('permitrootlogin', 'yes'))
    // Пароли выключены: root только по ключу — не дыра, но и не идеал.
    if (status === 'ok') status = 'warn'
  } else if (root === 'no') {
    findings.push(ru.facts.setting('permitrootlogin', 'no'))
  } else if (ROOT_KEY_ONLY.has(root)) {
    findings.push(ru.facts.setting('permitrootlogin', policy.permitRootLogin ?? root))
  } else if (root.length === 0) {
    findings.push(ru.facts.setting('permitrootlogin', 'prohibit-password (по умолчанию)'))
  }

  if (policy.pubkeyAuthentication === false) {
    findings.push(ru.facts.setting('pubkeyauthentication', 'no'))
    if (status === 'ok') status = 'warn'
  }

  if (
    passwords === null &&
    kbd === null &&
    policy.permitRootLogin === null &&
    policy.pubkeyAuthentication === null
  ) {
    return { status: 'unknown', findings: [ru.facts.noConfig()], fix: 'common.sudo' }
  }
  return { status, findings, fix: 'ssh.auth' }
}

export const sshAuth: Check = {
  id: 'ssh.auth',
  section: 1,
  severity: 'critical',
  async run(ctx) {
    if (!isLinux(ctx)) return skipped(ru.facts.notLinux())

    const result = await ctx.run('sshd', ['-T'])
    let configText: string | null = null
    if (result.ok) {
      configText = result.stdout
    } else {
      configText = await ctx.read('/etc/ssh/sshd_config')
      if (configText === null) return unavailable('sshd -T', result)
    }

    return evaluateSshPolicy(sshPolicy(parseSshdConfig(configText)))
  },
}
