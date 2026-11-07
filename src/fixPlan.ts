import { ru } from './i18n/ru'
import { getRecipe, pickVariant, renderRecipe } from './recipes/index'
import type { RecipeSnippet, Stack } from './recipes/types'
import {
  SEVERITY_RANK,
  STATUS_RANK,
  type CheckReport,
  type JsonReport,
  type Severity,
  type Status,
} from './types'

/** Рецепт шага плана: выбранный вариант, команда проверки и другие стеки */
export interface FixPlanRecipe {
  stack: Stack | null
  steps: string[]
  snippet?: RecipeSnippet
  verify: RecipeSnippet
  risks: string[]
  otherStacks: Stack[]
}

/** Один шаг плана починки: только fail и warn, сначала дыры */
export interface FixPlanStep {
  id: string
  title: string
  problem: string
  status: Status
  severity: Severity
  findings: string[]
  recipe: FixPlanRecipe
}

export interface FixPlan {
  domain: string
  stacks: Stack[]
  csp: string | null
  plan: FixPlanStep[]
}

/** Порядок как в текстовом отчёте: fail → warn, внутри — важность по убыванию */
function compareSteps(a: CheckReport, b: CheckReport): number {
  const byStatus = STATUS_RANK[a.status] - STATUS_RANK[b.status]
  if (byStatus !== 0) return byStatus
  return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
}

/** План починки из отчёта сайта: только fail и warn, с рецептом под найденный стек */
export function buildFixPlan(report: JsonReport, domain: string): FixPlan {
  const stacks = report.site?.stacks ?? []
  const csp = report.site?.csp ?? null
  const steps: FixPlanStep[] = []

  for (const check of [...report.checks].filter(
    (item) => item.status === 'fail' || item.status === 'warn',
  ).sort(compareSteps)) {
    const recipe = getRecipe(check.id, 'ru')
    if (recipe === null) continue

    const rendered = renderRecipe(recipe, {
      domain,
      ...(csp === null ? {} : { csp }),
    })
    const picked = pickVariant(rendered, stacks)
    const variant = picked.variant
    const otherStacks = (Object.keys(rendered.stacks) as Stack[]).filter(
      (stack) => stack !== picked.stack,
    )

    const planRecipe: FixPlanRecipe = {
      stack: picked.stack,
      steps: variant.steps,
      verify: rendered.verify,
      risks: rendered.risks,
      otherStacks,
    }
    if (variant.snippet !== undefined) planRecipe.snippet = variant.snippet

    const text = ru.checks[check.id]
    steps.push({
      id: check.id,
      title: text?.title ?? check.id,
      problem: text?.problem ?? '',
      status: check.status,
      severity: check.severity,
      findings: check.findings,
      recipe: planRecipe,
    })
  }

  return { domain, stacks, csp, plan: steps }
}
