import { recipes as enRecipes } from './en'
import { recipes as ruRecipes } from './ru'
import type { Recipe, RecipeLocale, RecipeVariant, RecipeVars, Stack } from './types'

export { detectStack } from './detect'
export { collectResources, buildCsp } from './csp'
export type * from './types'

/** Безопасный стартовый CSP, если пользователь не передал свой */
const START_CSP =
  "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"

/** Рецепт по id проверки; null, если проверка неизвестна */
export function getRecipe(checkId: string, locale: RecipeLocale = 'ru'): Recipe | null {
  const source = locale === 'en' ? enRecipes : ruRecipes
  return source[checkId] ?? null
}

function substitute(text: string, vars: RecipeVars): string {
  const csp = vars.csp ?? START_CSP
  return text.split('{domain}').join(vars.domain).split('{csp}').join(csp)
}

function renderVariant(variant: RecipeVariant, vars: RecipeVars): RecipeVariant {
  const rendered: RecipeVariant = { steps: variant.steps.map((step) => substitute(step, vars)) }
  if (variant.snippet !== undefined) {
    rendered.snippet = {
      lang: variant.snippet.lang,
      code: substitute(variant.snippet.code, vars),
    }
  }
  return rendered
}

/** Подставляет домен и CSP во все тексты и фрагменты, не меняя исходный рецепт */
export function renderRecipe(recipe: Recipe, vars: RecipeVars): Recipe {
  const stacks: Recipe['stacks'] = {}
  for (const stack of Object.keys(recipe.stacks) as Stack[]) {
    const variant = recipe.stacks[stack]
    if (variant !== undefined) stacks[stack] = renderVariant(variant, vars)
  }
  return {
    checkId: recipe.checkId,
    stacks,
    generic: renderVariant(recipe.generic, vars),
    verify: { lang: recipe.verify.lang, code: substitute(recipe.verify.code, vars) },
    risks: recipe.risks.map((risk) => substitute(risk, vars)),
  }
}

/** Первый стек из списка, для которого есть вариант; иначе общий путь */
export function pickVariant(
  recipe: Recipe,
  stacks: readonly Stack[],
): { stack: Stack | null; variant: RecipeVariant } {
  for (const stack of stacks) {
    const variant = recipe.stacks[stack]
    if (variant !== undefined) return { stack, variant }
  }
  return { stack: null, variant: recipe.generic }
}
