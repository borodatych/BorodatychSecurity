import { ru } from '../../i18n/ru'
import { parseSshdConfig, sshPolicy } from '../../parsers/system'
import type { Check } from '../../types'
import { isLinux, skipped, unavailable } from '../shared'

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

    const record = parseSshdConfig(configText)
    const policy = sshPolicy(record)
    const findings: string[] = []
    let bad = false
    let warn = false
    let known = false

    if (policy.passwordAuthentication === true) {
      findings.push(ru.facts.setting('passwordauthentication', 'yes'))
      bad = true
      known = true
    } else if (policy.passwordAuthentication === false) {
      known = true
    } else {
      findings.push(ru.facts.setting('passwordauthentication', 'не найден, по умолчанию обычно yes'))
      warn = true
    }

    if ((policy.permitRootLogin ?? '').toLowerCase() === 'yes') {
      findings.push(ru.facts.setting('permitrootlogin', 'yes'))
      bad = true
      known = true
    } else if (policy.permitRootLogin !== null) {
      findings.push(ru.facts.setting('permitrootlogin', policy.permitRootLogin))
      known = true
    }

    if (policy.kbdInteractiveAuthentication === true) {
      findings.push(ru.facts.setting('kbdinteractiveauthentication', 'yes'))
      bad = true
      known = true
    } else if (policy.kbdInteractiveAuthentication === false) {
      known = true
    }

    if (policy.pubkeyAuthentication === false) {
      findings.push(ru.facts.setting('pubkeyauthentication', 'no'))
      warn = true
    }

    if (!known && findings.length === 0) {
      return { status: 'unknown', findings: [ru.facts.noConfig()], fix: 'common.sudo' }
    }
    if (findings.length === 0) {
      findings.push(ru.facts.setting('passwordauthentication', 'no'))
      findings.push(
        ru.facts.setting('permitrootlogin', policy.permitRootLogin ?? 'prohibit-password'),
      )
    }

    const status = bad ? 'fail' : warn ? 'warn' : 'ok'
    return { status, findings, fix: 'ssh.auth' }
  },
}
