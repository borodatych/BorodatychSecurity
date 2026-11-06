import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import { audit, serverChecks, siteChecks } from './audit'
import { ru } from './i18n/ru'
import {
  parseAuditServerArgs,
  parseAuditSiteArgs,
  parseExplainCheckArgs,
  toSelection,
} from './mcpArgs'
import { checkInfo, knownCheckIds, listCheckInfo } from './mcpCatalog'
import { selectChecks } from './run'
import { VERSION } from './version'

/** Описания инструментов для агента: по-английски, кратко, с обещанием «только чтение» */
const descriptions = {
  auditServer:
    'Runs the read-only security audit of the local server: OS support, SSH, open ports, firewall, ' +
    'Docker isolation, fail2ban/CrowdSec, backups. Website checks are excluded; use audit_site for those. ' +
    'Optional only/skip take check ids from list_checks. Returns the CLI --json report (Russian findings ' +
    'and fixes). This tool only reads the server and never changes it: fix only after the user agrees; ' +
    'the tool itself never changes the server.',
  auditSite:
    'Runs the read-only external audit of a website over HTTPS: leaked secrets, source maps, security ' +
    'headers, TLS, CORS, cookies, rate limiting and version banners. domain must be a bare hostname ' +
    '(no scheme, path, port or IP). ratelimit is off by default because it sends 30 rapid requests; ' +
    "turn it on only with the user's consent. Returns the CLI --json report. This tool only reads: " +
    'fix only after the user agrees; the tool itself never changes the server.',
  explainCheck:
    'Explains one check by id: what it verifies, how it is checked, what counts as a problem, and how ' +
    'to fix it. Read-only. Use list_checks first to pick a known id.',
  listChecks:
    'Lists every available check with id, section, severity and title. Read-only. Call it before ' +
    'audit_server, audit_site or explain_check to choose valid ids.',
} as const

const titles = {
  auditServer: 'Audit server',
  auditSite: 'Audit website',
  explainCheck: 'Explain check',
  listChecks: 'List checks',
} as const

function jsonResult(value: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] }
}

function errorResult(message: string): CallToolResult {
  return { content: [{ type: 'text', text: message }], isError: true }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** MCP-сервер: те же проверки, что у CLI, и то же обещание «только чтение» */
export function createMcpServer(): McpServer {
  const server = new McpServer(
    { name: 'borodatych-security', version: VERSION },
    { capabilities: { tools: {} } },
  )

  server.registerTool(
    'audit_server',
    {
      title: titles.auditServer,
      description: descriptions.auditServer,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      inputSchema: {
        only: z.array(z.string()).optional().describe('Check ids to run; omit to run all server checks.'),
        skip: z.array(z.string()).optional().describe('Check ids to skip.'),
      },
    },
    async (args) => {
      try {
        const parsed = parseAuditServerArgs(args)
        const selected = selectChecks(serverChecks(), toSelection(parsed))
        return jsonResult(await audit(selected))
      } catch (error) {
        return errorResult(ru.mcp.auditFailed(messageOf(error)))
      }
    },
  )

  server.registerTool(
    'audit_site',
    {
      title: titles.auditSite,
      description: descriptions.auditSite,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
      inputSchema: {
        domain: z.string().describe('Bare hostname, for example example.ru. No scheme, path, port or IP.'),
        ratelimit: z
          .boolean()
          .optional()
          .describe('Also probe the rate limit (30 rapid requests). Off by default.'),
      },
    },
    async (args) => {
      try {
        const parsed = parseAuditSiteArgs(args)
        const selection = parsed.ratelimit ? {} : { skip: ['web.ratelimit'] }
        const selected = selectChecks(siteChecks(), selection)
        return jsonResult(await audit(selected, { domain: parsed.domain }))
      } catch (error) {
        return errorResult(ru.mcp.auditFailed(messageOf(error)))
      }
    },
  )

  server.registerTool(
    'explain_check',
    {
      title: titles.explainCheck,
      description: descriptions.explainCheck,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      inputSchema: {
        id: z.string().describe('Check id from list_checks, for example ssh.auth.'),
      },
    },
    (args) => {
      try {
        const { id } = parseExplainCheckArgs(args)
        const info = checkInfo(id)
        if (info === null) {
          return errorResult(ru.mcp.unknownCheck(id, knownCheckIds().join(', ')))
        }
        return jsonResult(info)
      } catch (error) {
        return errorResult(messageOf(error))
      }
    },
  )

  server.registerTool(
    'list_checks',
    {
      title: titles.listChecks,
      description: descriptions.listChecks,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      inputSchema: {},
    },
    () => jsonResult(listCheckInfo()),
  )

  return server
}

/** Поднять MCP-сервер по stdio; ошибки проверок не роняют сервер */
export async function runMcpServer(): Promise<void> {
  const server = createMcpServer()
  await server.connect(new StdioServerTransport())
}
