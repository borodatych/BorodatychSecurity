import { describe, expect, test } from 'bun:test'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { createMcpServer, type McpServerOptions } from '../src/mcp'
import type { FixPlanStep } from '../src/fixPlan'
import type { TlsHandshakeFn } from '../src/types'

const FOREIGN = 'https://borodatych-security.invalid'
const HTML = '<!doctype html><html><head><title>ok</title></head><body></body></html>'

const ALLOWED = {
  allowed: true,
  via: 'free',
  freeLeft: 2,
  passUntil: null,
  domain: 'example.ru',
}

const DENIED = {
  allowed: false,
  via: null,
  freeLeft: 0,
  passUntil: null,
  domain: 'example.ru',
}

interface FakeApi {
  access: unknown
  status?: number
}

function siteResponse(url: URL): Response {
  const headers: Record<string, string> = {
    'content-type': 'text/html',
    server: 'nginx/1.24.0',
    'access-control-allow-origin': FOREIGN,
    'access-control-allow-credentials': 'true',
  }
  if (url.pathname === '/.env') {
    return new Response('APP_KEY=base64:secret\nDB_PASSWORD=hunter2', { status: 200, headers })
  }
  if (url.pathname === '/.borodatych-security-missing') {
    return new Response(HTML, { status: 404, headers })
  }
  return new Response(HTML, { status: 200, headers })
}

function fakeFetch(api: FakeApi): typeof fetch {
  const impl = (input: string): Promise<Response> => {
    const url = new URL(input)
    if (url.pathname === '/api/cli/v1/access') {
      return Promise.resolve(
        new Response(JSON.stringify(api.access), {
          status: api.status ?? 200,
          headers: { 'content-type': 'application/json' },
        }),
      )
    }
    return Promise.resolve(siteResponse(url))
  }
  return impl as unknown as typeof fetch
}

const tlsHandshake: TlsHandshakeFn = ({ maxVersion }) =>
  Promise.resolve(
    maxVersion === 'TLSv1.1'
      ? { validTo: null, error: 'refused' }
      : { validTo: '2027-11-07T00:00:00.000Z', error: null },
  )

interface Session {
  client: Client
  close: () => Promise<void>
}

async function connect(options: McpServerOptions): Promise<Session> {
  const server = createMcpServer(options)
  const client = new Client({ name: 'test-client', version: '0.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)])
  return {
    client,
    close: async () => {
      await client.close()
      await server.close()
    },
  }
}

function textOf(result: CallToolResult): string {
  const block = result.content[0]
  if (block?.type !== 'text') throw new Error('нет текстового ответа')
  return block.text
}

describe('MCP: инструменты починки', () => {
  test('tools/list: новые инструменты только для чтения', async () => {
    const session = await connect({ token: null, env: {} })
    try {
      const { tools } = await session.client.listTools()
      const names = tools.map((tool) => tool.name)
      expect(names).toContain('fix_plan')
      expect(names).toContain('get_recipe')
      expect(names).toContain('verify_fix')
      for (const name of ['fix_plan', 'get_recipe', 'verify_fix']) {
        const tool = tools.find((item) => item.name === name)
        expect(tool?.annotations?.readOnlyHint).toBe(true)
        expect(tool?.description?.length ?? 0).toBeGreaterThan(20)
      }
    } finally {
      await session.close()
    }
  })

  test('fix_plan: только fail и warn, fail вперёд, severity по убыванию, рецепт под nginx', async () => {
    const session = await connect({
      fetch: fakeFetch({ access: ALLOWED }),
      tlsHandshake,
      token: 'bsec_test',
    })
    try {
      const result = (await session.client.callTool({
        name: 'fix_plan',
        arguments: { domain: 'example.ru' },
      })) as CallToolResult
      expect(result.isError ?? false).toBe(false)
      const plan = JSON.parse(textOf(result)) as {
        domain: string
        stacks: string[]
        plan: FixPlanStep[]
      }
      expect(plan.domain).toBe('example.ru')
      expect(plan.stacks).toEqual(['nginx'])
      expect(plan.plan.map((step) => step.id)).toEqual([
        'web.secrets',
        'web.cors',
        'web.headers',
        'web.banner',
      ])
      expect(plan.plan.slice(0, 2).every((step) => step.status === 'fail')).toBe(true)
      expect(plan.plan.slice(2).every((step) => step.status === 'warn')).toBe(true)
      const headers = plan.plan.find((step) => step.id === 'web.headers')
      expect(headers?.recipe.stack).toBe('nginx')
      expect(headers?.recipe.steps.length).toBeGreaterThan(0)
      expect(headers?.recipe.verify.code.length).toBeGreaterThan(0)
      expect(headers?.recipe.otherStacks).toContain('caddy')
      expect(JSON.stringify(headers)).not.toContain('{domain}')
    } finally {
      await session.close()
    }
  })

  test('fix_plan без доступа — ошибка инструмента с подсказкой про кабинет', async () => {
    const session = await connect({
      fetch: fakeFetch({ access: DENIED }),
      tlsHandshake,
      token: 'bsec_test',
    })
    try {
      const result = (await session.client.callTool({
        name: 'fix_plan',
        arguments: { domain: 'example.ru' },
      })) as CallToolResult
      expect(result.isError).toBe(true)
      expect(textOf(result)).toContain('Бесплатные домены закончились')
      expect(textOf(result)).toContain('/my/checks')
    } finally {
      await session.close()
    }
  })

  test('fix_plan без токена — просим войти', async () => {
    const session = await connect({ token: null, env: {} })
    try {
      const result = (await session.client.callTool({
        name: 'fix_plan',
        arguments: { domain: 'example.ru' },
      })) as CallToolResult
      expect(result.isError).toBe(true)
      expect(textOf(result)).toContain('npx @borodatych/security login')
    } finally {
      await session.close()
    }
  })

  test('get_recipe бесплатен, работает без токена и подставляет домен', async () => {
    const session = await connect({ token: null, env: {} })
    try {
      const result = (await session.client.callTool({
        name: 'get_recipe',
        arguments: { checkId: 'web.headers', domain: 'example.ru', stack: 'nginx' },
      })) as CallToolResult
      expect(result.isError ?? false).toBe(false)
      const output = JSON.parse(textOf(result)) as {
        checkId: string
        stack: string
        steps: string[]
        snippet?: { code: string }
        verify: { code: string }
        risks: string[]
        otherStacks: string[]
      }
      expect(output.checkId).toBe('web.headers')
      expect(output.stack).toBe('nginx')
      expect(output.steps.length).toBeGreaterThan(0)
      expect(output.snippet?.code.length ?? 0).toBeGreaterThan(0)
      expect(output.verify.code.length).toBeGreaterThan(0)
      expect(output.risks.length).toBeGreaterThan(0)
      expect(output.otherStacks).toContain('caddy')
      expect(JSON.stringify(output)).not.toContain('{domain}')
    } finally {
      await session.close()
    }
  })

  test('get_recipe: неизвестный checkId — ошибка со списком', async () => {
    const session = await connect({ token: null, env: {} })
    try {
      const result = (await session.client.callTool({
        name: 'get_recipe',
        arguments: { checkId: 'no.such' },
      })) as CallToolResult
      expect(result.isError).toBe(true)
      expect(textOf(result)).toContain('no.such')
      expect(textOf(result)).toContain('web.headers')
    } finally {
      await session.close()
    }
  })

  test('verify_fix для серверной проверки — ошибка про audit_server', async () => {
    const session = await connect({
      fetch: fakeFetch({ access: ALLOWED }),
      tlsHandshake,
      token: 'bsec_test',
    })
    try {
      const result = (await session.client.callTool({
        name: 'verify_fix',
        arguments: { checkId: 'ssh.auth', domain: 'example.ru' },
      })) as CallToolResult
      expect(result.isError).toBe(true)
      expect(textOf(result)).toContain('audit_server')
    } finally {
      await session.close()
    }
  })

  test('verify_fix: одна проверка сайта, fixed=false при warn', async () => {
    const session = await connect({
      fetch: fakeFetch({ access: ALLOWED }),
      tlsHandshake,
      token: 'bsec_test',
    })
    try {
      const result = (await session.client.callTool({
        name: 'verify_fix',
        arguments: { checkId: 'web.headers', domain: 'example.ru' },
      })) as CallToolResult
      expect(result.isError ?? false).toBe(false)
      const output = JSON.parse(textOf(result)) as {
        id: string
        status: string
        findings: string[]
        fixed: boolean
      }
      expect(output.id).toBe('web.headers')
      expect(output.status).toBe('warn')
      expect(output.findings.length).toBeGreaterThan(0)
      expect(output.fixed).toBe(false)
    } finally {
      await session.close()
    }
  })
})
