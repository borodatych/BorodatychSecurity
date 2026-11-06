import { describe, expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { checks } from '../src/registry'

interface DocRow {
  id: string
  section: number
}

function readDocRows(): DocRow[] {
  const path = join(import.meta.dir, '..', 'docs', 'checks.md')
  const text = readFileSync(path, 'utf8')
  const rows: DocRow[] = []
  let section = 0
  for (const raw of text.split(/\r?\n/)) {
    const heading = /^##\s+(\d+)\./.exec(raw)
    if (heading !== null) {
      section = Number(heading[1])
      continue
    }
    if (!raw.startsWith('|')) continue
    const cells = raw.split('|').map((cell) => cell.trim())
    const id = cells[1] ?? ''
    if (id.length === 0 || id === 'id' || /^-+$/.test(id)) continue
    rows.push({ id, section })
  }
  return rows
}

const SECTION_5_EXPECTED = [
  'web.secrets',
  'web.sourcemaps',
  'web.headers',
  'web.tls',
  'web.cors',
  'web.cookies',
  'web.ratelimit',
  'web.banner',
]

describe('registry и docs/checks.md', () => {
  const rows = readDocRows()
  const section5 = rows.filter((row) => row.section === 5)

  test('id в registry равны всем таблицам разделов 1–6', () => {
    const registryIds = checks.map((check) => check.id).sort()
    const docIds = rows.map((row) => row.id).sort()
    expect(registryIds).toEqual(docIds)
  })

  test('раздел 5 реализован полным списком', () => {
    expect(section5.map((row) => row.id).sort()).toEqual([...SECTION_5_EXPECTED].sort())
    const registryIds = new Set(checks.map((check) => check.id))
    for (const id of SECTION_5_EXPECTED) expect(registryIds.has(id)).toBe(true)
  })

  test('нет дублей, разделы совпадают с документом', () => {
    const ids = checks.map((check) => check.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const check of checks) {
      const row = rows.find((item) => item.id === check.id)
      expect(row?.section).toBe(check.section)
      expect(['critical', 'high', 'medium', 'low']).toContain(check.severity)
    }
  })

  test('у каждой проверки есть тексты и исправление', async () => {
    const { ru } = await import('../src/i18n/ru')
    for (const check of checks) {
      expect(ru.checks[check.id]?.title.length).toBeGreaterThan(0)
      expect(ru.checks[check.id]?.problem.length).toBeGreaterThan(0)
      expect(ru.fixes[check.id]?.length).toBeGreaterThan(0)
    }
  })
})
