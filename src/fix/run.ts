import { AccessError, requireAccess } from '../account/require'
import { audit, siteChecks } from '../audit'
import { ru } from '../i18n/ru'
import { DEFAULT_CSP, getRecipe, pickVariant, renderRecipe } from '../recipes/index'
import type { Stack } from '../recipes/types'
import { checks as registry } from '../registry'
import { selectChecks } from '../run'
import type { Check, JsonReport, TlsHandshakeFn } from '../types'
import { applyPlan, rollback } from './apply'
import { parseFixArgs, normalizeDomain, type FixArgs } from './args'
import {
  CADDYFILE_PATH,
  caddySitesForDomain,
  planCaddyFix,
  type CaddyPlan,
} from './caddy'
import { createFixCtx } from './ctx'
import { unifiedDiff } from './diff'
import {
  NGINX_HEADERS_SNIPPET_PATH,
  NGINX_RATELIMIT_PATH,
  NGINX_SNIPPET_PATH,
  httpIncludesConfD,
  parseNginxDump,
  planNginxFix,
  serversForDomain,
  type NginxFile,
  type NginxPlan,
} from './nginx'
import type { FixCtx, FixPlan, FixSkip, FixServer } from './types'

/** Проверки, которые fix умеет менять сам */
export const AUTO_FIX_CHECKS = [
  'web.headers',
  'web.banner',
  'web.sourcemaps',
  'web.ratelimit',
] as const

/** По умолчанию не трогаем ratelimit: проверка шлёт 30 быстрых запросов */
const DEFAULT_AUDIT_CHECKS = ['web.headers', 'web.banner', 'web.sourcemaps'] as const

const BACKUP_ROOT = '/var/backups/borodatych-security'

export interface FixDeps {
  requireAccess?: (domain: string) => Promise<unknown>
  auditSite?: (checks: readonly Check[], domain: string) => Promise<JsonReport>
  fetch?: typeof fetch
  tlsHandshake?: TlsHandshakeFn
}

export interface FixRunOptions {
  args: FixArgs
  ctx?: FixCtx
  deps?: FixDeps
}

interface RunState {
  ctx: FixCtx
  json: boolean
  say: (text: string) => void
}

function say(state: RunState, text: string): void {
  state.say(`${text}\n`)
}

function fail(ctx: FixCtx, message: string): void {
  ctx.err(`${ru.report.error(message)}\n`)
}

function stamp(date: Date): string {
  return date.toISOString()
}

function covered(ids: readonly string[]): string[] {
  const result: string[] = []
  for (const id of ids) {
    if ((AUTO_FIX_CHECKS as readonly string[]).includes(id) && !result.includes(id)) {
      result.push(id)
    }
  }
  return result
}

function problemChecks(report: JsonReport, ids: readonly string[]): string[] {
  const result: string[] = []
  for (const id of ids) {
    const check = report.checks.find((item) => item.id === id)
    if (check !== undefined && (check.status === 'fail' || check.status === 'warn')) {
      result.push(id)
    }
  }
  return result
}

function stackList(server: FixServer | null, report: JsonReport | null): Stack[] {
  if (server === 'nginx') return ['nginx']
  if (server === 'caddy') return ['caddy']
  return report?.site?.stacks ?? []
}

function printRecipe(
  state: RunState,
  options: {
    checkId: string
    domain: string
    csp: string
    stacks: readonly Stack[]
    fallback: string | null
  },
): void {
  const recipe = getRecipe(options.checkId, 'ru')
  if (recipe === null) return
  const rendered = renderRecipe(recipe, { domain: options.domain, csp: options.csp })
  const picked = pickVariant(rendered, options.stacks)
  const stack = picked.stack ?? options.fallback ?? ru.fix.recipeStackGeneric
  say(state, ru.fix.recipeTitle(options.checkId, stack))
  for (const step of picked.variant.steps) say(state, ru.fix.recipeStep(step))
  if (picked.variant.snippet !== undefined) {
    say(state, ru.fix.recipeConfig(picked.variant.snippet.lang))
    say(state, picked.variant.snippet.code)
  }
  say(state, ru.fix.recipeVerify(rendered.verify.code))
  for (const risk of rendered.risks) say(state, ru.fix.recipeRisk(risk))
}

function printSkipped(state: RunState, skipped: readonly FixSkip[]): void {
  for (const item of skipped) {
    say(state, ru.fix.planSkip(item.target, item.detail))
  }
}

function printPlan(state: RunState, plan: FixPlan): void {
  say(state, ru.fix.planTitle(plan.domain, plan.server === 'caddy' ? ru.fix.serverCaddy : ru.fix.serverNginx))
  say(state, ru.fix.planChecks(plan.checks.join(', ')))
  for (const edit of plan.edits) {
    say(state, ru.fix.planEdit(edit.path))
    say(state, ru.fix.diffTitle(edit.path))
    const diff = unifiedDiff(edit.path, edit.before, edit.after)
    say(state, diff.length > 0 ? diff : ru.fix.emptyDiff)
  }
  printSkipped(state, plan.skipped)
}

function recipeSkips(skipped: readonly FixSkip[]): string[] {
  const ids: string[] = []
  for (const item of skipped) {
    if (item.reason === 'already') continue
    if (!ids.includes(item.checkId)) ids.push(item.checkId)
  }
  return ids
}

function printRecipes(
  state: RunState,
  plan: FixPlan,
  extraIds: readonly string[],
  report: JsonReport | null,
): void {
  const stacks = stackList(plan.server, report)
  const fallback = plan.server === 'nginx' ? 'nginx' : plan.server === 'caddy' ? 'caddy' : null
  const ids = [...new Set([...extraIds, ...recipeSkips(plan.skipped)])]
  for (const id of ids) {
    printRecipe(state, {
      checkId: id,
      domain: plan.domain,
      csp: plan.csp ?? DEFAULT_CSP,
      stacks,
      fallback,
    })
  }
}

async function detectServer(
  ctx: FixCtx,
  domain: string,
): Promise<{
  server: FixServer | null
  nginxFiles: NginxFile[] | null
  caddyText: string | null
  ambiguous: boolean
  found: boolean
}> {
  const dump = await ctx.run('nginx', ['-T'])
  let nginxFiles: NginxFile[] | null = null
  if (dump.ok) {
    const paths = parseNginxDump(dump.stdout)
    const files: NginxFile[] = []
    for (const path of paths) {
      const text = await ctx.read(path)
      if (text !== null) files.push({ path, text })
    }
    if (files.length > 0) nginxFiles = files
  }

  const caddyVersion = await ctx.run('caddy', ['version'])
  const caddyText = await ctx.read(CADDYFILE_PATH)

  const nginxHas = nginxFiles?.some((file) => serversForDomain(file, domain).length > 0) ?? false
  const caddyHas =
    caddyVersion.ok &&
    caddyText !== null &&
    caddySitesForDomain(caddyText, domain).length > 0

  if (nginxHas && caddyHas) {
    return { server: null, nginxFiles, caddyText, ambiguous: true, found: true }
  }
  const server: FixServer | null = nginxHas ? 'nginx' : caddyHas ? 'caddy' : null
  return {
    server,
    nginxFiles,
    caddyText,
    ambiguous: false,
    found: server !== null,
  }
}

async function buildPlan(
  ctx: FixCtx,
  server: FixServer,
  domain: string,
  ids: readonly string[],
  csp: string,
  nginxFiles: NginxFile[] | null,
  caddyText: string | null,
): Promise<FixPlan> {
  if (server === 'nginx') {
    const files = nginxFiles ?? []
    const plan: NginxPlan = planNginxFix({
      domain,
      checks: ids,
      csp,
      files,
      httpIncludesConfD: httpIncludesConfD(files),
      snippetBefore: await ctx.read(NGINX_SNIPPET_PATH),
      headersSnippetBefore: await ctx.read(NGINX_HEADERS_SNIPPET_PATH),
      ratelimitBefore: await ctx.read(NGINX_RATELIMIT_PATH),
    })
    return { domain, server, checks: [...ids], edits: plan.edits, skipped: plan.skipped, csp }
  }

  const plan: CaddyPlan = planCaddyFix({ domain, checks: ids, csp, text: caddyText ?? '' })
  return { domain, server, checks: [...ids], edits: plan.edits, skipped: plan.skipped, csp }
}

interface JsonOutcome {
  ok: boolean
  domain: string
  server: FixServer | null
  dryRun: boolean
  backupDir: string | null
  changes: { path: string; kind: string }[]
  skipped: FixSkip[]
  recheck: { id: string; status: string; fixed: boolean }[]
  rollback: string | null
  error?: string
}

async function runRollbackCommand(
  ctx: FixCtx,
  dir: string,
  json: boolean,
): Promise<number> {
  if (ctx.platform !== 'linux') {
    fail(ctx, ru.fix.notLinux)
    return 2
  }
  if (ctx.uid !== 0) {
    fail(ctx, ru.fix.needRoot)
    return 2
  }
  const outcome = await rollback(ctx, dir)
  if (json) {
    ctx.out(
      `${JSON.stringify(
        {
          ok: outcome.ok,
          rollback: dir,
          server: outcome.manifest?.server ?? null,
          ...(outcome.error === null ? {} : { error: outcome.error }),
        },
        null,
        2,
      )}\n`,
    )
  } else if (outcome.ok) {
    ctx.out(`${ru.fix.rollbackDone}\n`)
  } else {
    fail(ctx, outcome.error ?? ru.fix.manifestMissing(dir))
  }
  return outcome.ok ? 0 : 1
}

/** Команда fix: требования, доступ, аудит, план, подтверждение, применение и перепроверка */
export async function runFix(options: FixRunOptions): Promise<number> {
  const ctx = options.ctx ?? createFixCtx()
  const args = options.args
  const deps = options.deps ?? {}
  const state: RunState = {
    ctx,
    json: args.json,
    say: (text) => {
      if (!args.json) ctx.out(text)
    },
  }

  if (args.rollback !== undefined) {
    return runRollbackCommand(ctx, args.rollback, args.json)
  }

  if (ctx.platform !== 'linux') {
    fail(ctx, ru.fix.notLinux)
    return 2
  }
  if (ctx.uid !== 0) {
    fail(ctx, ru.fix.needRoot)
    return 2
  }
  if (args.domain === undefined) {
    fail(ctx, ru.fix.domainRequired)
    return 2
  }

  let domain: string
  try {
    domain = normalizeDomain(args.domain)
  } catch (error) {
    fail(ctx, error instanceof Error ? error.message : String(error))
    return 2
  }

  try {
    await (deps.requireAccess ?? ((value: string) => requireAccess(value)))(domain)
  } catch (error) {
    if (error instanceof AccessError) {
      fail(ctx, error.message)
      return 2
    }
    fail(ctx, error instanceof Error ? error.message : String(error))
    return 2
  }

  // Неизвестный id — ошибка CLI, как у обычной проверки
  try {
    selectChecks(registry, { only: args.only ?? [] })
  } catch (error) {
    fail(ctx, error instanceof Error ? error.message : String(error))
    return 2
  }

  const requested = args.only ?? [...DEFAULT_AUDIT_CHECKS]
  const selected = covered(requested)
  const uncovered = requested.filter((id) => !(AUTO_FIX_CHECKS as readonly string[]).includes(id))

  if (selected.length === 0) {
    say(state, ru.fix.nothingSelected)
    const emptyReport: JsonReport | null = null
    const emptyPlan: FixPlan = {
      domain,
      server: null,
      checks: [],
      edits: [],
      skipped: [],
      csp: DEFAULT_CSP,
    }
    printRecipes(state, emptyPlan, uncovered, emptyReport)
    return 0
  }

  const checkObjects = selectChecks(siteChecks(), { only: selected })
  let report: JsonReport
  try {
    const auditSite =
      deps.auditSite ??
      ((checks: readonly Check[], value: string) =>
        audit(checks, {
          domain: value,
          ...(deps.fetch === undefined ? {} : { fetch: deps.fetch }),
          ...(deps.tlsHandshake === undefined ? {} : { tlsHandshake: deps.tlsHandshake }),
        }))
    report = await auditSite(checkObjects, domain)
  } catch (error) {
    fail(ctx, ru.fix.auditFailed(error instanceof Error ? error.message : String(error)))
    return 2
  }

  const csp = report.site?.csp ?? DEFAULT_CSP
  const problems = problemChecks(report, selected)

  if (problems.length === 0) {
    say(state, ru.fix.noFixes)
    const emptyPlan: FixPlan = {
      domain,
      server: null,
      checks: [],
      edits: [],
      skipped: [],
      csp,
    }
    printRecipes(state, emptyPlan, uncovered, report)
    return 0
  }

  const detected = await detectServer(ctx, domain)
  if (detected.ambiguous) {
    say(state, ru.fix.serverAmbiguous(domain))
  } else if (!detected.found) {
    say(
      state,
      detected.nginxFiles === null && detected.caddyText === null
        ? ru.fix.serverUnknown
        : ru.fix.serverNoDomain(domain),
    )
  }

  let plan: FixPlan
  if (detected.server === null) {
    plan = {
      domain,
      server: null,
      checks: problems,
      edits: [],
      skipped: problems.map((id) => ({
        checkId: id,
        target: 'server',
        reason: 'unsupported',
        detail: ru.fix.recipeNoAuto(id),
      })),
      csp,
    }
  } else {
    plan = await buildPlan(
      ctx,
      detected.server,
      domain,
      problems,
      csp,
      detected.nginxFiles,
      detected.caddyText,
    )
  }

  printPlan(state, plan)
  printRecipes(state, plan, uncovered, report)

  if (plan.edits.length === 0) {
    const outcome: JsonOutcome = {
      ok: true,
      domain,
      server: plan.server,
      dryRun: args.dryRun,
      backupDir: null,
      changes: [],
      skipped: plan.skipped,
      recheck: [],
      rollback: null,
    }
    if (args.json) ctx.out(`${JSON.stringify(outcome, null, 2)}\n`)
    return 0
  }

  if (args.dryRun) {
    say(state, ru.fix.dryRun)
    if (args.json) {
      const outcome: JsonOutcome = {
        ok: true,
        domain,
        server: plan.server,
        dryRun: true,
        backupDir: null,
        changes: plan.edits.map((edit) => ({ path: edit.path, kind: edit.kind })),
        skipped: plan.skipped,
        recheck: [],
        rollback: null,
      }
      ctx.out(`${JSON.stringify(outcome, null, 2)}\n`)
    }
    return 0
  }

  if (!args.yes) {
    if (!ctx.stdinIsTTY) {
      fail(ctx, ru.fix.noTTY)
      return 2
    }
    const confirmed = await ctx.confirm(ru.fix.confirm)
    if (!confirmed) {
      say(state, ru.fix.declined)
      return 0
    }
  }

  const backupDir = `${BACKUP_ROOT}/${stamp(ctx.now)}`
  const applied = await applyPlan(ctx, plan, plan.server ?? 'nginx', backupDir)
  if (!applied.ok) {
    fail(ctx, applied.error ?? ru.fix.validateFailed(''))
    if (applied.manifest !== null) {
      say(state, ru.fix.rollbackHint(applied.manifest.rollbackCommand))
    }
    if (args.json) {
      const outcome: JsonOutcome = {
        ok: false,
        domain,
        server: plan.server,
        dryRun: false,
        backupDir,
        changes: plan.edits.map((edit) => ({ path: edit.path, kind: edit.kind })),
        skipped: plan.skipped,
        recheck: [],
        rollback: applied.manifest?.rollbackCommand ?? null,
        error: applied.error ?? '',
      }
      ctx.out(`${JSON.stringify(outcome, null, 2)}\n`)
    }
    return 1
  }

  say(state, ru.fix.backupAt(backupDir))
  say(state, ru.fix.applied)

  if (plan.server !== null) {
    say(state, ru.fix.recheckWait)
    await ctx.sleep(5000)
  }

  const recheckIds = problems.filter((id) => selected.includes(id))
  let recheckReport: JsonReport | null = null
  if (recheckIds.length > 0) {
    try {
      const auditSite =
        deps.auditSite ??
        ((checks: readonly Check[], value: string) =>
          audit(checks, {
            domain: value,
            ...(deps.fetch === undefined ? {} : { fetch: deps.fetch }),
            ...(deps.tlsHandshake === undefined ? {} : { tlsHandshake: deps.tlsHandshake }),
          }))
      recheckReport = await auditSite(
        selectChecks(siteChecks(), { only: recheckIds }),
        domain,
      )
    } catch {
      recheckReport = null
    }
  }

  const recheck: { id: string; status: string; fixed: boolean }[] = []
  for (const id of recheckIds) {
    const result = recheckReport?.checks.find((item) => item.id === id)
    const status = result?.status ?? 'unknown'
    const fixed = status === 'ok'
    recheck.push({ id, status, fixed })
    say(state, fixed ? ru.fix.recheckFixed(id) : ru.fix.recheckStill(id))
  }
  const notFixed = recheck.some((item) => !item.fixed)
  if (notFixed) say(state, ru.fix.cdnHint)

  const command = applied.manifest?.rollbackCommand ?? ru.fix.rollbackCommand(backupDir)
  say(state, ru.fix.rollbackHint(command))

  if (args.json) {
    const outcome: JsonOutcome = {
      ok: !notFixed,
      domain,
      server: plan.server,
      dryRun: false,
      backupDir,
      changes: plan.edits.map((edit) => ({ path: edit.path, kind: edit.kind })),
      skipped: plan.skipped,
      recheck,
      rollback: command,
    }
    ctx.out(`${JSON.stringify(outcome, null, 2)}\n`)
  }

  return notFixed ? 1 : 0
}

/** Разбор и запуск из main: ошибки аргументов остаются ошибками CLI */
export async function fixFromArgs(
  argv: readonly string[],
  options: Omit<FixRunOptions, 'args'> = {},
): Promise<number> {
  if (argv.includes('--help') || argv.includes('-h')) {
    const ctx = options.ctx ?? createFixCtx()
    ctx.out(`${ru.fix.helpText.join('\n')}\n`)
    return 0
  }
  let args: FixArgs
  try {
    args = parseFixArgs(argv)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const ctx = options.ctx ?? createFixCtx()
    ctx.err(`${ru.report.error(message)}\n`)
    return 2
  }
  return runFix({ ...options, args })
}
