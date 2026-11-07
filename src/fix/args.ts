import { parseArgs } from 'node:util'
import { domainToASCII } from 'node:url'
import { CliError } from '../args'
import { ru } from '../i18n/ru'
import { domainProblem } from '../mcpArgs'

/** Аргументы команды fix: единственной команды пакета, которая меняет сервер */
export interface FixArgs {
  domain?: string
  only?: string[]
  yes: boolean
  dryRun: boolean
  json: boolean
  rollback?: string
}

function list(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined
  const items = value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
  return items.length > 0 ? items : undefined
}

/** Разбор аргументов fix без побочных эффектов; ошибка разбора — CliError */
export function parseFixArgs(argv: readonly string[]): FixArgs {
  let parsed
  try {
    parsed = parseArgs({
      args: [...argv],
      strict: true,
      allowPositionals: false,
      options: {
        domain: { type: 'string' },
        only: { type: 'string' },
        yes: { type: 'boolean', default: false },
        'dry-run': { type: 'boolean', default: false },
        json: { type: 'boolean', default: false },
        rollback: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    })
  } catch (error) {
    throw new CliError(error instanceof Error ? error.message : String(error))
  }

  const values = parsed.values
  const args: FixArgs = {
    yes: values.yes,
    dryRun: values['dry-run'],
    json: values.json,
  }
  const only = list(values.only)
  if (only !== undefined) args.only = only
  if (values.domain !== undefined && values.domain.trim().length > 0) {
    args.domain = values.domain.trim()
  }
  if (values.rollback !== undefined && values.rollback.trim().length > 0) {
    args.rollback = values.rollback.trim()
  }
  if (args.rollback !== undefined && args.domain !== undefined) {
    throw new CliError(ru.fix.rollbackWithDomain)
  }
  return args
}

/** Имя хоста в том же виде, что у проверок сайта: punycode, нижний регистр */
export function normalizeDomain(value: string): string {
  const problem = domainProblem(value)
  if (problem !== null) throw new CliError(ru.fix.domainInvalid(problem))
  return domainToASCII(value).toLowerCase()
}
