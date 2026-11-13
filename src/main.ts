import { spawn } from 'node:child_process'
import { hostname } from 'node:os'
import { ApiClient, ApiError } from './account/api'
import { apiBase, clearToken, clientName, readToken, writeToken } from './account/config'
import { CliError, isAccountCommand, parseAccountArgs, parseCliArgs } from './args'
import { audit } from './audit'
import { fixFromArgs } from './fix/run'
import { ru } from './i18n/ru'
import { runMcpServer } from './mcp'
import { checks as registry } from './registry'
import { exitCodeFor } from './report/json'
import { renderText } from './report/text'
import { selectChecks } from './run'
import { VERSION } from './version'

/** Дата без времени для whoami */
function dateOnly(iso: string): string {
  return /^\d{4}-\d{2}-\d{2}/.test(iso) ? iso.slice(0, 10) : iso
}

/** Текст ошибки сервиса для человека */
function apiErrorText(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.kind === 'unauthorized') return ru.account.tokenInvalid
    if (error.kind === 'rate_limited') return ru.account.rateLimited(error.retryAfter)
    if (error.kind === 'network') return ru.account.network(error.message)
    return ru.account.serverError(error.status)
  }
  return error instanceof Error ? error.message : String(error)
}

/** Открыть браузер; если команды нет — вход продолжается по ссылке в терминале */
function openBrowser(url: string): void {
  const command =
    process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open'
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url]
  try {
    const child = spawn(command, args, { detached: true, stdio: 'ignore' })
    child.on('error', () => {
      // браузера нет — не ошибка, ссылка уже напечатана
    })
    child.unref()
  } catch {
    // запуск браузера не удался — вход продолжается вручную
  }
}

async function runLogin(): Promise<number> {
  const client = new ApiClient({ baseUrl: apiBase(process.env) })
  try {
    const device = await client.startDevice(clientName(hostname()))
    process.stdout.write(
      `${ru.account.loginCode(device.userCode)}\n` +
        `${ru.account.loginUrl(device.verificationUrl)}\n` +
        `${ru.account.loginWaiting}\n`,
    )
    openBrowser(device.verificationUrl)
    const outcome = await client.pollToken({
      deviceCode: device.deviceCode,
      interval: device.interval,
      expiresIn: device.expiresIn,
    })
    if (outcome.status === 'denied') {
      process.stderr.write(`${ru.report.error(ru.account.loginDenied)}\n`)
      return 2
    }
    if (outcome.status === 'expired') {
      process.stderr.write(`${ru.report.error(ru.account.loginExpired)}\n`)
      return 2
    }
    writeToken(outcome.token)
    process.stdout.write(`${ru.account.greeting(outcome.user.email)}\n`)
    return 0
  } catch (error) {
    process.stderr.write(`${ru.report.error(apiErrorText(error))}\n`)
    return 2
  }
}

function runLogout(): number {
  const removed = clearToken()
  process.stdout.write(`${removed ? ru.account.logoutDone : ru.account.logoutNone}\n`)
  return 0
}

async function runWhoami(json: boolean): Promise<number> {
  const token = readToken()
  if (token === null) {
    process.stderr.write(`${ru.report.error(ru.account.loginRequired)}\n`)
    return 2
  }
  const client = new ApiClient({ baseUrl: apiBase(process.env), token })
  try {
    const me = await client.me()
    if (json) {
      process.stdout.write(`${JSON.stringify(me, null, 2)}\n`)
      return 0
    }
    process.stdout.write(`${ru.account.whoamiEmail(me.email)}\n`)
    process.stdout.write(`${ru.account.whoamiFree(me.access.freeLeft, me.access.freeLimit)}\n`)
    if (me.access.freeSites.length === 0 && me.access.passes.length === 0) {
      process.stdout.write(`${ru.account.whoamiNoAccess}\n`)
      return 0
    }
    process.stdout.write(`${ru.account.whoamiAccess}\n`)
    for (const site of me.access.freeSites) {
      process.stdout.write(
        `${ru.account.whoamiFreeSite(site.domain, dateOnly(site.createdAt))}\n`,
      )
    }
    for (const pass of me.access.passes) {
      process.stdout.write(`${ru.account.whoamiPass(pass.domain, dateOnly(pass.until))}\n`)
    }
    return 0
  } catch (error) {
    process.stderr.write(`${ru.report.error(apiErrorText(error))}\n`)
    return 2
  }
}

/**
 * Точка входа CLI; отдельно от bin, чтобы MCP мог импортировать main.
 * null — процесс оставлен MCP-серверу на stdio (завершится, когда закроется stdin)
 */
export async function main(argv: readonly string[]): Promise<number | null> {
  if (argv[0] === 'mcp') {
    if (argv.length > 1) {
      process.stderr.write(`${ru.report.error(ru.mcp.noArgs)}\n${ru.report.hint}\n`)
      return 2
    }
    try {
      await runMcpServer()
      return null
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      process.stderr.write(`${ru.report.error(message)}\n`)
      return 2
    }
  }

  const first = argv[0]
  if (first === 'fix') {
    return await fixFromArgs(argv.slice(1))
  }
  if (isAccountCommand(first)) {
    let accountOptions: ReturnType<typeof parseAccountArgs>
    try {
      accountOptions = parseAccountArgs(argv.slice(1))
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      process.stderr.write(`${ru.report.error(message)}\n${ru.report.hint}\n`)
      return 2
    }
    if (first === 'login') return await runLogin()
    if (first === 'logout') return runLogout()
    return await runWhoami(accountOptions.json)
  }

  let options
  try {
    options = parseCliArgs(argv)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`${ru.report.error(message)}\n${ru.report.hint}\n`)
    return 2
  }

  if (options.help) {
    process.stdout.write(`${ru.report.help.join('\n')}\n`)
    return 0
  }
  if (options.version) {
    process.stdout.write(`${ru.report.version(VERSION)}\n`)
    return 0
  }

  try {
    const selected = selectChecks(registry, options)
    const report = await audit(selected, {
      ...(options.domain === undefined ? {} : { domain: options.domain }),
      ...(options.canary === undefined ? {} : { canaryPaths: options.canary }),
    })

    if (options.json) {
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
    } else {
      const color = process.stdout.isTTY && process.env.NO_COLOR === undefined
      process.stdout.write(`${renderText(report, { color, quiet: options.quiet })}\n`)
    }
    return exitCodeFor(report.checks)
  } catch (error) {
    if (error instanceof CliError) {
      process.stderr.write(`${ru.report.error(error.message)}\n${ru.report.hint}\n`)
    } else {
      const message = error instanceof Error ? error.message : String(error)
      process.stderr.write(`${ru.report.error(message)}\n`)
    }
    return 2
  }
}
