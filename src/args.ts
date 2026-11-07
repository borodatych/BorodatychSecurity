import { parseArgs } from 'node:util'

export interface CliOptions {
  json: boolean
  quiet: boolean
  help: boolean
  version: boolean
  only?: string[]
  skip?: string[]
  domain?: string
}

export class CliError extends Error {}

function list(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined
  const items = value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
  return items.length > 0 ? items : undefined
}

/** Разбор аргументов без побочных эффектов; ошибка разбора — CliError */
export function parseCliArgs(argv: readonly string[]): CliOptions {
  let parsed
  try {
    parsed = parseArgs({
      args: [...argv],
      strict: true,
      allowPositionals: false,
      options: {
        json: { type: 'boolean', default: false },
        quiet: { type: 'boolean', default: false },
        only: { type: 'string' },
        skip: { type: 'string' },
        domain: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false },
      },
    })
  } catch (error) {
    throw new CliError(error instanceof Error ? error.message : String(error))
  }

  const values = parsed.values
  const options: CliOptions = {
    json: values.json,
    quiet: values.quiet,
    help: values.help,
    version: values.version,
  }
  const only = list(values.only)
  const skip = list(values.skip)
  if (only !== undefined) options.only = only
  if (skip !== undefined) options.skip = skip
  if (values.domain !== undefined && values.domain.trim().length > 0) {
    options.domain = values.domain.trim()
  }
  return options
}
