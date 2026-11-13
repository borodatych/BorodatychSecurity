import { afterAll, describe, expect, test } from 'bun:test'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ru } from '../src/i18n/ru'
import { createMcpServer } from '../src/mcp'
import {
  ToolInputError,
  domainProblem,
  parseAuditServerArgs,
  parseAuditSiteArgs,
  parseExplainCheckArgs,
  toSelection,
} from '../src/mcpArgs'
import { checkInfo, knownCheckIds, listCheckInfo } from '../src/mcpCatalog'

describe('разбор аргументов инструментов MCP', () => {
  test('audit_server: пустые аргументы и фильтры', () => {
    expect(parseAuditServerArgs({})).toEqual({})
    expect(parseAuditServerArgs({ only: [' base.os ', 'base.os'], skip: ['ops.monitor'] })).toEqual({
      only: ['base.os'],
      skip: ['ops.monitor'],
    })
    expect(parseAuditServerArgs({ only: [] })).toEqual({})
    expect(toSelection(parseAuditServerArgs({ only: ['base.os'] }))).toEqual({ only: ['base.os'] })
  })

  test('audit_server: мусор вместо списка — ошибка', () => {
    expect(() => parseAuditServerArgs({ only: 'base.os' })).toThrow(ToolInputError)
    expect(() => parseAuditServerArgs({ skip: [1] })).toThrow(ToolInputError)
    expect(() => parseAuditServerArgs({ only: ['  '] })).toThrow(ToolInputError)
    expect(() => parseAuditServerArgs(null)).toThrow(ToolInputError)
  })

  test('audit_site: только имя хоста, ratelimit по умолчанию false', () => {
    expect(parseAuditSiteArgs({ domain: 'example.ru' })).toEqual({
      domain: 'example.ru',
      ratelimit: false,
    })
    expect(parseAuditSiteArgs({ domain: 'Sub.Example.RU', ratelimit: true })).toEqual({
      domain: 'sub.example.ru',
      ratelimit: true,
    })
    expect(parseAuditSiteArgs({ domain: 'xn--e1afmkfd.xn--p1ai' }).domain).toBe(
      'xn--e1afmkfd.xn--p1ai',
    )
    expect(parseAuditSiteArgs({ domain: 'пример.рф' }).domain).toBe('xn--e1afmkfd.xn--p1ai')
  })

  test('audit_site: схема, путь, порт, IP, пробелы и мусор отклоняются', () => {
    const bad = [
      'https://example.ru',
      'example.ru/path',
      'example.ru?x=1',
      'example.ru:443',
      'user@example.ru',
      '1.2.3.4',
      '2001:db8::1',
      'exa mple.ru',
      '',
      'localhost',
      '-bad.example.ru',
      'example.ru.',
    ]
    for (const domain of bad) {
      expect(() => parseAuditSiteArgs({ domain })).toThrow(ToolInputError)
    }
    expect(domainProblem('https://example.ru')).toBe(ru.mcp.domainScheme)
    expect(domainProblem('1.2.3.4')).toBe(ru.mcp.domainIp)
    expect(domainProblem('example.ru')).toBeNull()
  })

  test('audit_site: ratelimit не булев — ошибка', () => {
    expect(() => parseAuditSiteArgs({ domain: 'example.ru', ratelimit: 'yes' })).toThrow(
      ToolInputError,
    )
    expect(() => parseAuditSiteArgs({})).toThrow(ToolInputError)
  })

  test('explain_check: id обязателен, пробелы обрезаются', () => {
    expect(parseExplainCheckArgs({ id: ' ssh.auth ' })).toEqual({ id: 'ssh.auth' })
    expect(() => parseExplainCheckArgs({})).toThrow(ToolInputError)
    expect(() => parseExplainCheckArgs({ id: '   ' })).toThrow(ToolInputError)
  })
})

describe('explain_check и list_checks', () => {
  test('известная проверка: что, как, проблема, чем чинить', () => {
    const info = checkInfo('ssh.auth')
    expect(info).not.toBeNull()
    expect(info?.id).toBe('ssh.auth')
    expect(info?.section).toBe(1)
    expect(info?.sectionTitle).toBe('База')
    expect(info?.severity).toBe('critical')
    expect(info?.title).toBe('SSH только по ключам')
    expect(info?.how).toContain('sshd -T')
    expect(info?.problem).toContain('пароли')
    expect(info?.fix).toContain('выключить пароли')
  })

  test('неизвестная проверка — null, известные id перечислены', () => {
    expect(checkInfo('no.such')).toBeNull()
    const ids = knownCheckIds()
    expect(ids.length).toBe(28)
    expect(ids).toContain('web.secrets')
  })

  test('list_checks: id, раздел, важность, название для всех проверок', () => {
    const all = listCheckInfo()
    expect(all.length).toBe(knownCheckIds().length)
    for (const info of all) {
      expect(info.id.length).toBeGreaterThan(0)
      expect(info.sectionTitle.length).toBeGreaterThan(0)
      expect(info.title.length).toBeGreaterThan(0)
      expect(['critical', 'high', 'medium', 'low']).toContain(info.severity)
    }
  })

  test('колонка «как» в каталоге совпадает с docs/checks.md', () => {
    const path = join(import.meta.dir, '..', 'docs', 'checks.md')
    const rows = new Map<string, string>()
    for (const raw of readFileSync(path, 'utf8').split(/\r?\n/)) {
      if (!raw.startsWith('|')) continue
      const cells = raw.split('|').map((cell) => cell.trim())
      const id = cells[1] ?? ''
      if (id.length === 0 || id === 'id' || /^-+$/.test(id)) continue
      rows.set(id, cells[3] ?? '')
    }
    expect(Object.keys(ru.how).sort()).toEqual([...rows.keys()].sort())
    for (const [id, how] of rows) expect(ru.how[id]).toBe(how)
  })
})

function textOf(result: CallToolResult): string {
  const block = result.content[0]
  if (block?.type !== 'text') throw new Error('нет текстового ответа')
  return block.text
}

describe('MCP-сервер по InMemoryTransport', () => {
  const server = createMcpServer()
  const client = new Client({ name: 'test-client', version: '0.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

  const ready = Promise.all([client.connect(clientTransport), server.connect(serverTransport)])

  afterAll(async () => {
    await client.close()
    await server.close()
  })

  test('tools/list: семь инструментов с описаниями только для чтения', async () => {
    await ready
    const { tools } = await client.listTools()
    expect(tools.map((tool) => tool.name).sort()).toEqual([
      'audit_server',
      'audit_site',
      'explain_check',
      'fix_plan',
      'get_recipe',
      'list_checks',
      'verify_fix',
    ])
    for (const tool of tools) {
      expect(tool.description?.length ?? 0).toBeGreaterThan(20)
      expect(tool.annotations?.readOnlyHint).toBe(true)
    }
    const site = tools.find((tool) => tool.name === 'audit_site')
    expect(site?.inputSchema.required).toEqual(['domain'])
    expect(site?.description).toContain('fix only after the user agrees')
  })

  test('list_checks: 28 проверок в JSON', async () => {
    await ready
    const result = (await client.callTool({ name: 'list_checks', arguments: {} })) as CallToolResult
    expect(result.isError ?? false).toBe(false)
    const list = JSON.parse(textOf(result)) as { id: string; severity: string }[]
    expect(list.length).toBe(28)
    expect(list.map((item) => item.id)).toContain('web.ratelimit')
  })

  test('explain_check: известная проверка', async () => {
    await ready
    const result = (await client.callTool({
      name: 'explain_check',
      arguments: { id: 'web.headers' },
    })) as CallToolResult
    expect(result.isError ?? false).toBe(false)
    const info = JSON.parse(textOf(result)) as {
      section: number
      severity: string
      title: string
      how: string
      problem: string
      fix: string
    }
    expect(info.section).toBe(5)
    expect(info.severity).toBe('medium')
    expect(info.title).toBe('заголовки безопасности')
    expect(info.fix).toContain('HSTS')
    expect(info.how.length).toBeGreaterThan(0)
  })

  test('explain_check: неизвестный id — ошибка инструмента с перечнем', async () => {
    await ready
    const result = (await client.callTool({
      name: 'explain_check',
      arguments: { id: 'no.such' },
    })) as CallToolResult
    expect(result.isError).toBe(true)
    expect(textOf(result)).toContain('no.such')
    expect(textOf(result)).toContain('ssh.auth')
  })

  test('отчёт MCP: строки-приглашения про сайт нет', async () => {
    await ready
    const result = (await client.callTool({
      name: 'audit_server',
      arguments: { only: ['ops.monitor'] },
    })) as CallToolResult
    expect(result.isError ?? false).toBe(false)
    const text = textOf(result)
    const report = JSON.parse(text) as { checks: { id: string }[] }
    expect(report.checks.map((check) => check.id)).toEqual(['ops.monitor'])
    expect(text).not.toContain('security.borodatych.ru')
    expect(text).not.toContain(ru.report.promo)
  })

  test('audit_server не берёт проверки сайта, сервер остаётся живым', async () => {
    await ready
    const bad = (await client.callTool({
      name: 'audit_server',
      arguments: { only: ['web.secrets'] },
    })) as CallToolResult
    expect(bad.isError).toBe(true)
    expect(textOf(bad)).toContain('web.secrets')

    const alive = (await client.callTool({ name: 'list_checks', arguments: {} })) as CallToolResult
    expect(alive.isError ?? false).toBe(false)
  })

  test('audit_site: домен со схемой — ошибка инструмента', async () => {
    await ready
    const result = (await client.callTool({
      name: 'audit_site',
      arguments: { domain: 'https://example.ru' },
    })) as CallToolResult
    expect(result.isError).toBe(true)
    expect(textOf(result)).toContain('домен не принят')
  })
})
