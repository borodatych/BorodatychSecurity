import { parseArgs } from 'node:util'

export interface CliOptions {
  json: boolean
  quiet: boolean
  help: boolean
  version: boolean
  only?: string[]
  skip?: string[]
  domain?: string
  canary?: string[]
}

export class CliError extends Error {}

/** Команды входа и профиля: отдельные подкоманды, а не флаги отчёта */
export const ACCOUNT_COMMANDS = ['login', 'logout', 'whoami'] as const
export type AccountCommand = (typeof ACCOUNT_COMMANDS)[number]

export interface AccountCommandOptions {
  json: boolean
}

export function isAccountCommand(value: string | undefined): value is AccountCommand {
  return value !== undefined && (ACCOUNT_COMMANDS as readonly string[]).includes(value)
}

/** Разбор аргументов login/logout/whoami: только --json, без позиционных */
export function parseAccountArgs(argv: readonly string[]): AccountCommandOptions {
  let parsed
  try {
    parsed = parseArgs({
      args: [...argv],
      strict: true,
      allowPositionals: false,
      options: {
        json: { type: 'boolean', default: false },
      },
    })
  } catch (error) {
    throw new CliError(error instanceof Error ? error.message : String(error))
  }
  return { json: parsed.values.json }
}

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
        canary: { type: 'string' },
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
  const canary = list(values.canary)
  if (canary !== undefined) options.canary = canary
  if (values.domain !== undefined && values.domain.trim().length > 0) {
    options.domain = values.domain.trim()
  }
  return options
}
