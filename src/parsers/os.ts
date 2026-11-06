import { OS_SUPPORT, type EolEntry } from '../data/os'
import type { Status } from '../types'

/** Разбор /etc/os-release: KEY=value и KEY="value" */
export function parseOsRelease(text: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line.length === 0 || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq <= 0) continue
    const key = line.slice(0, eq).trim()
    let value = line.slice(eq + 1).trim()
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1)
    }
    result[key] = value
  }
  return result
}

export function daysBetween(from: Date, to: Date): number {
  return Math.ceil((to.getTime() - from.getTime()) / 86_400_000)
}

export interface EolState {
  known: boolean
  until: string | null
  daysLeft: number | null
  status: Status
}

export function evaluateEol(
  table: Record<string, EolEntry>,
  key: string,
  now: Date,
): EolState {
  const entry = table[key]
  if (entry === undefined) {
    return { known: false, until: null, daysLeft: null, status: 'unknown' }
  }
  const until = new Date(`${entry.until}T23:59:59Z`)
  const daysLeft = daysBetween(now, until)
  let status: Status = 'ok'
  if (daysLeft < 0) status = 'fail'
  else if (daysLeft <= 90) status = 'warn'
  return { known: true, until: entry.until, daysLeft, status }
}

export interface OsSupportState extends EolState {
  key: string
}

/** Срок поддержки ОС по id и VERSION_ID; неизвестное — unknown */
export function evaluateOsSupport(
  release: Record<string, string>,
  now: Date,
  table: Record<string, EolEntry> = OS_SUPPORT,
): OsSupportState {
  const id = (release.ID ?? '').toLowerCase()
  const version = release.VERSION_ID ?? ''
  const key = `${id}:${version}`
  return { key, ...evaluateEol(table, key, now) }
}

export interface ParsedVersion {
  major: number
  minor: number
  patch: number
}

/** Первая версия вида 1.2.3 в выводе команды */
export function parseVersion(text: string): ParsedVersion | null {
  const match = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(text)
  if (match === null) return null
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3] ?? '0'),
  }
}

/** Ключ таблицы поддержки: node/bun — мажор, остальные — мажор.минор */
export function runtimeKey(
  table: Record<string, EolEntry>,
  version: ParsedVersion,
  precision: 'major' | 'minor',
): string | null {
  const minorKey = `${version.major}.${version.minor}`
  if (precision === 'minor' && minorKey in table) return minorKey
  const majorKey = String(version.major)
  if (majorKey in table) return majorKey
  if (minorKey in table) return minorKey
  return null
}
