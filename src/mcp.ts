import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import { requireAccess, type RequireAccessOptions } from './account/require'
import { audit, serverChecks, siteChecks, type AuditOptions } from './audit'
import { buildFixPlan } from './fixPlan'
import { ru } from './i18n/ru'
import {
  parseAuditServerArgs,
  parseAuditSiteArgs,
  parseExplainCheckArgs,
  parseFixPlanArgs,
  parseGetRecipeArgs,
  parseVerifyFixArgs,
  toSelection,
} from './mcpArgs'
import {
  checkInfo,
  knownCheckIds,
  listCheckInfo,
  toolDescriptions,
  toolTitles,
} from './mcpCatalog'
import { getRecipe, pickVariant, renderRecipe } from './recipes/index'
import type { RecipeSnippet, Stack } from './recipes/types'
import { selectChecks } from './run'
import type { TlsHandshakeFn } from './types'
import { VERSION } from './version'

/** Подменяемые сеть, окружение и токен: в тестах ничего реального не трогаем */
export interface McpServerOptions {
  fetch?: typeof fetch
  tlsHandshake?: TlsHandshakeFn
  env?: NodeJS.ProcessEnv
  uid?: number | null
  lookupUser?: (name: string) => { home: string; uid: number; gid: number } | null
  apiBase?: string
  token?: string | null
}

/** Домен для подстановки, когда get_recipe позвали без domain */
const SAMPLE_DOMAIN = 'example.ru'

function accessOptions(options: McpServerOptions): RequireAccessOptions {
  const result: RequireAccessOptions = {}
  if (options.env !== undefined) result.env = options.env
  if (options.uid !== undefined) result.uid = options.uid
  if (options.lookupUser !== undefined) result.lookupUser = options.lookupUser
  if (options.fetch !== undefined) result.fetch = options.fetch
  if (options.apiBase !== undefined) result.baseUrl = options.apiBase
  if (options.token !== undefined) result.token = options.token
  return result
}

function siteAuditOptions(options: McpServerOptions, domain: string): AuditOptions {
  return {
    domain,
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.tlsHandshake === undefined ? {} : { tlsHandshake: options.tlsHandshake }),
  }
}

interface RecipeOutput {
  checkId: string
  stack: Stack | null
  stacks: Stack[]
  steps: string[]
  snippet?: RecipeSnippet
  verify: RecipeSnippet
  risks: string[]
  otherStacks: Stack[]
}

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

/** Рецепт для get_recipe и fix_plan: выбранный стек, шаги, конфиг и другие стеки */
function recipeOutput(
  checkId: string,
  stack: Stack | undefined,
  domain: string,
): RecipeOutput | null {
  const recipe = getRecipe(checkId, 'ru')
  if (recipe === null) return null
  const rendered = renderRecipe(recipe, { domain })
  const picked = pickVariant(rendered, stack === undefined ? [] : [stack])
  const available = Object.keys(rendered.stacks) as Stack[]
  const output: RecipeOutput = {
    checkId,
    stack: picked.stack,
    stacks: available,
    steps: picked.variant.steps,
    verify: rendered.verify,
    risks: rendered.risks,
    otherStacks: available.filter((item) => item !== picked.stack),
  }
  if (picked.variant.snippet !== undefined) output.snippet = picked.variant.snippet
  return output
}

/** MCP-сервер: те же проверки, что у CLI, и то же обещание «только чтение» */
export function createMcpServer(options: McpServerOptions = {}): McpServer {
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

  server.registerTool(
    'fix_plan',
    {
      title: toolTitles.fixPlan,
      description: toolDescriptions.fixPlan,
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
      let domain = ''
      let ratelimit = false
      try {
        const parsed = parseFixPlanArgs(args)
        domain = parsed.domain
        ratelimit = parsed.ratelimit
      } catch (error) {
        return errorResult(messageOf(error))
      }
      try {
        await requireAccess(domain, accessOptions(options))
      } catch (error) {
        return errorResult(messageOf(error))
      }
      try {
        const selection = ratelimit ? {} : { skip: ['web.ratelimit'] }
        const selected = selectChecks(siteChecks(), selection)
        const report = await audit(selected, siteAuditOptions(options, domain))
        return jsonResult(buildFixPlan(report, domain))
      } catch (error) {
        return errorResult(ru.mcp.auditFailed(messageOf(error)))
      }
    },
  )

  server.registerTool(
    'get_recipe',
    {
      title: toolTitles.getRecipe,
      description: toolDescriptions.getRecipe,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      inputSchema: {
        checkId: z.string().describe('Check id from list_checks, for example web.headers.'),
        stack: z
          .string()
          .optional()
          .describe('nginx, caddy, apache, npm, traefik, cloudflare, express or nextjs. Omit for generic.'),
        domain: z
          .string()
          .optional()
          .describe('Optional bare hostname; only fills {domain} placeholders in the recipe.'),
      },
    },
    (args) => {
      try {
        const parsed = parseGetRecipeArgs(args)
        const output = recipeOutput(parsed.checkId, parsed.stack, parsed.domain ?? SAMPLE_DOMAIN)
        if (output === null) {
          return errorResult(ru.mcp.unknownCheck(parsed.checkId, knownCheckIds().join(', ')))
        }
        return jsonResult(output)
      } catch (error) {
        return errorResult(messageOf(error))
      }
    },
  )

  server.registerTool(
    'verify_fix',
    {
      title: toolTitles.verifyFix,
      description: toolDescriptions.verifyFix,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
      inputSchema: {
        checkId: z.string().describe('Website check id from section 5, for example web.headers.'),
        domain: z.string().describe('Bare hostname, for example example.ru. No scheme, path, port or IP.'),
      },
    },
    async (args) => {
      let domain = ''
      let checkId = ''
      try {
        const parsed = parseVerifyFixArgs(args)
        domain = parsed.domain
        checkId = parsed.checkId
      } catch (error) {
        return errorResult(messageOf(error))
      }
      try {
        await requireAccess(domain, accessOptions(options))
      } catch (error) {
        return errorResult(messageOf(error))
      }

      const info = checkInfo(checkId)
      if (info === null) {
        return errorResult(ru.mcp.unknownCheck(checkId, knownCheckIds().join(', ')))
      }
      if (info.section !== 5) return errorResult(ru.mcp.serverCheck(checkId))
      const check = siteChecks().find((item) => item.id === checkId)
      if (check === undefined) {
        return errorResult(ru.mcp.unknownCheck(checkId, knownCheckIds().join(', ')))
      }

      try {
        const report = await audit([check], siteAuditOptions(options, domain))
        const result = report.checks[0]
        if (result === undefined) return errorResult(ru.mcp.auditFailed(checkId))
        return jsonResult({
          id: result.id,
          status: result.status,
          severity: result.severity,
          findings: result.findings,
          fixed: result.status === 'ok',
        })
      } catch (error) {
        return errorResult(ru.mcp.auditFailed(messageOf(error)))
      }
    },
  )

  return server
}

/** Поднять MCP-сервер по stdio; ошибки проверок не роняют сервер */
export async function runMcpServer(): Promise<void> {
  const server = createMcpServer()
  await server.connect(new StdioServerTransport())
}
