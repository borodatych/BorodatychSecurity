import { domainToASCII } from 'node:url'
import { ru } from './i18n/ru'
import type { Selection } from './run'

/** Ошибка разбора аргументов инструмента MCP: текст уходит агенту как ошибка инструмента */
export class ToolInputError extends Error {}

export interface AuditServerArgs {
  only?: string[]
  skip?: string[]
}

export interface AuditSiteArgs {
  domain: string
  ratelimit: boolean
}

export interface ExplainCheckArgs {
  id: string
}

function asRecord(input: unknown): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new ToolInputError(ru.mcp.invalidArgument('arguments'))
  }
  return input as Record<string, unknown>
}

function stringList(value: unknown, name: string): string[] | undefined {
  if (value === undefined) return undefined
  if (!Array.isArray(value)) throw new ToolInputError(ru.mcp.invalidList(name))
  const items: string[] = []
  for (const item of value) {
    if (typeof item !== 'string') throw new ToolInputError(ru.mcp.invalidList(name))
    const trimmed = item.trim()
    if (trimmed.length === 0) throw new ToolInputError(ru.mcp.invalidList(name))
    items.push(trimmed)
  }
  return items.length === 0 ? undefined : [...new Set(items)]
}

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/

/** Причина, по которой строка не годится как имя хоста; null — годится */
export function domainProblem(value: string): string | null {
  if (value.length === 0) return ru.mcp.domainEmpty
  if (value.length > 253) return ru.mcp.domainTooLong
  if (/\s/.test(value)) return ru.mcp.domainSpace
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return ru.mcp.domainScheme
  if (/[/?#]/.test(value)) return ru.mcp.domainPath
  if (/[:@[\]]/.test(value)) return ru.mcp.domainPort
  if (IPV4_RE.test(value)) return ru.mcp.domainIp

  // Кириллицу и другие IDN приводим к punycode: дальше проверяем только ASCII
  const ascii = domainToASCII(value)
  if (ascii.length === 0 || ascii.length > 253) return ru.mcp.domainFormat

  const labels = ascii.split('.')
  if (labels.length < 2) return ru.mcp.domainFormat
  if (labels.some((label) => !LABEL_RE.test(label))) return ru.mcp.domainFormat
  const last = labels[labels.length - 1] ?? ''
  if (/^\d+$/.test(last)) return ru.mcp.domainIp
  return null
}

export function parseAuditServerArgs(input: unknown): AuditServerArgs {
  const record = asRecord(input)
  const only = stringList(record.only, 'only')
  const skip = stringList(record.skip, 'skip')
  const args: AuditServerArgs = {}
  if (only !== undefined) args.only = only
  if (skip !== undefined) args.skip = skip
  return args
}

export function parseAuditSiteArgs(input: unknown): AuditSiteArgs {
  const record = asRecord(input)
  const domain = record.domain
  if (typeof domain !== 'string') throw new ToolInputError(ru.mcp.invalidArgument('domain'))
  const problem = domainProblem(domain)
  if (problem !== null) throw new ToolInputError(ru.mcp.invalidDomain(problem))

  const ratelimit = record.ratelimit
  if (ratelimit !== undefined && typeof ratelimit !== 'boolean') {
    throw new ToolInputError(ru.mcp.invalidBoolean('ratelimit'))
  }
  return { domain: domainToASCII(domain).toLowerCase(), ratelimit: ratelimit === true }
}

export function parseExplainCheckArgs(input: unknown): ExplainCheckArgs {
  const record = asRecord(input)
  const id = record.id
  if (typeof id !== 'string' || id.trim().length === 0) {
    throw new ToolInputError(ru.mcp.invalidId)
  }
  return { id: id.trim() }
}

/** Собрать выбор проверок без лишних undefined (exactOptionalPropertyTypes) */
export function toSelection(args: AuditServerArgs): Selection {
  const selection: Selection = {}
  if (args.only !== undefined) selection.only = args.only
  if (args.skip !== undefined) selection.skip = args.skip
  return selection
}
