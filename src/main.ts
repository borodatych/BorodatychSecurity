import { CliError, parseCliArgs } from './args'
import { audit } from './audit'
import { ru } from './i18n/ru'
import { runMcpServer } from './mcp'
import { checks as registry } from './registry'
import { exitCodeFor } from './report/json'
import { renderText } from './report/text'
import { selectChecks } from './run'
import { VERSION } from './version'

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
    const report = await audit(
      selected,
      options.domain === undefined ? {} : { domain: options.domain },
    )

    if (options.json) {
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
    } else {
      const color = process.stdout.isTTY && process.env.NO_COLOR === undefined
      process.stdout.write(`${renderText(report, { color })}\n`)
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
