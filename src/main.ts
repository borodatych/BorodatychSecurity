import { hostname } from 'node:os'
import { CliError, parseCliArgs } from './args'
import { createCtx } from './exec'
import { ru } from './i18n/ru'
import { checks as registry } from './registry'
import { buildJsonReport, exitCodeFor } from './report/json'
import { renderText } from './report/text'
import { runChecks, selectChecks } from './run'
import { VERSION } from './version'

/** Точка входа CLI; отдельно от bin, чтобы MCP мог импортировать main позже */
export async function main(argv: readonly string[]): Promise<number> {
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
    const ctx = createCtx(options.domain === undefined ? {} : { domain: options.domain })
    const startedAt = ctx.now.toISOString()
    const results = await runChecks(ctx, selected)
    const report = buildJsonReport(VERSION, hostname(), startedAt, results)

    if (options.json) {
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
    } else {
      const color = process.stdout.isTTY && process.env.NO_COLOR === undefined
      process.stdout.write(`${renderText(report, { color })}\n`)
    }
    return exitCodeFor(results)
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
