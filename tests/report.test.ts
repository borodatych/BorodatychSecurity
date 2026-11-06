import { describe, expect, test } from 'bun:test'
import { CliError, parseCliArgs } from '../src/args'
import { buildJsonReport, exitCodeFor } from '../src/report/json'
import { renderText } from '../src/report/text'
import { runChecks, selectChecks } from '../src/run'
import { checks } from '../src/registry'
import type { Check, CheckReport, Ctx } from '../src/types'

const SAMPLE: CheckReport[] = [
  {
    id: 'ssh.auth',
    section: 1,
    severity: 'critical',
    status: 'fail',
    findings: ['passwordauthentication yes'],
    fix: 'ssh.auth',
  },
  {
    id: 'base.os',
    section: 1,
    severity: 'high',
    status: 'ok',
    findings: ['система: Ubuntu 24.04.3 LTS'],
    fix: 'base.os',
  },
  {
    id: 'ops.monitor',
    section: 6,
    severity: 'medium',
    status: 'unknown',
    findings: ['проверка возможна только снаружи'],
    fix: 'ops.monitor',
  },
]

describe('JSON-отчёт и код выхода', () => {
  const report = buildJsonReport('0.1.0', 'host', '2026-11-06T00:00:00.000Z', SAMPLE)

  test('стабильная схема', () => {
    expect(Object.keys(report).sort()).toEqual(['checks', 'host', 'startedAt', 'version'])
    expect(report.version).toBe('0.1.0')
    expect(report.checks.length).toBe(3)
    for (const check of report.checks) {
      expect(Object.keys(check).sort()).toEqual([
        'findings',
        'fix',
        'id',
        'section',
        'severity',
        'status',
      ])
      expect(Array.isArray(check.findings)).toBe(true)
      expect(check.fix.length).toBeGreaterThan(0)
    }
    expect(report.checks[0]?.fix).toBe('выключить пароли, root только по ключу или никак')
    expect(() => JSON.parse(JSON.stringify(report)) as unknown).not.toThrow()
  })

  test('код выхода: 1 при fail, 0 без fail', () => {
    expect(exitCodeFor(SAMPLE)).toBe(1)
    expect(exitCodeFor(SAMPLE.filter((check) => check.status !== 'fail'))).toBe(0)
    expect(exitCodeFor([{ status: 'warn' }, { status: 'unknown' }, { status: 'skip' }])).toBe(0)
  })

  test('текст: сводка, разделы, худшие, без цвета', () => {
    const text = renderText(report, { color: false })
    expect(text).toContain('Итог: дыр 1')
    expect(text).toContain('Худшие')
    expect(text).toContain('1. База')
    expect(text).toContain('6. Хозяйство')
    expect(text).toContain('Чем чинить: выключить пароли')
    expect(text).not.toContain('\u001b[')
  })

  test('ok и skip: только findings, без «что значит» и «чем чинить»', () => {
    const okSample = SAMPLE[1]
    if (okSample === undefined) throw new Error('нет образца ok')
    for (const status of ['ok', 'skip'] as const) {
      const only = buildJsonReport('0.1.0', 'host', '2026-11-06T00:00:00.000Z', [
        { ...okSample, status },
      ])
      const text = renderText(only, { color: false })
      expect(text).not.toContain('Что значит')
      expect(text).not.toContain('Чем чинить')
    }
  })

  test('unknown: только подсказка, без «что значит»', () => {
    const unknownSample = SAMPLE[2]
    if (unknownSample === undefined) throw new Error('нет образца unknown')
    const only = buildJsonReport('0.1.0', 'host', '2026-11-06T00:00:00.000Z', [unknownSample])
    const text = renderText(only, { color: false })
    expect(text).not.toContain('Что значит')
    expect(text).toContain('Чем чинить: поставить Uptime Kuma')
  })
})

describe('аргументы', () => {
  test('флаги и списки', () => {
    const options = parseCliArgs([
      '--json',
      '--only',
      'base.os, ssh.auth',
      '--skip',
      'ops.monitor',
      '--domain',
      'example.ru',
    ])
    expect(options.json).toBe(true)
    expect(options.only).toEqual(['base.os', 'ssh.auth'])
    expect(options.skip).toEqual(['ops.monitor'])
    expect(options.domain).toBe('example.ru')
  })

  test('неизвестный флаг — ошибка CLI', () => {
    expect(() => parseCliArgs(['--nope'])).toThrow(CliError)
  })

  test('выбор проверок и неизвестный id', () => {
    expect(selectChecks(checks, { only: ['base.os'] }).map((check) => check.id)).toEqual(['base.os'])
    expect(selectChecks(checks, { skip: ['base.os'] }).some((check) => check.id === 'base.os')).toBe(
      false,
    )
    expect(() => selectChecks(checks, { only: ['no.such'] })).toThrow(CliError)
  })

  test('упавшая проверка даёт unknown и не роняет запуск', async () => {
    const broken: Check = {
      id: 'broken',
      section: 1,
      severity: 'low',
      run: () => Promise.reject(new Error('boom')),
    }
    const ctx = {} as Ctx
    const [result] = await runChecks(ctx, [broken])
    expect(result?.status).toBe('unknown')
  })
})
