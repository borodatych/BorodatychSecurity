/** Стек веб-сервера или приложения, под который есть свой рецепт */
export type Stack =
  | 'nginx'
  | 'caddy'
  | 'apache'
  | 'npm'
  | 'traefik'
  | 'cloudflare'
  | 'express'
  | 'nextjs'

/** Язык рецепта */
export type RecipeLocale = 'ru' | 'en'

/** Фрагмент конфига с подсветкой */
export interface RecipeSnippet {
  lang: 'nginx' | 'caddyfile' | 'apache' | 'yaml' | 'js' | 'bash' | 'ini' | 'text'
  code: string
}

/** Один путь починки: шаги и необязательный конфиг */
export interface RecipeVariant {
  steps: string[]
  snippet?: RecipeSnippet
}

/** Подробная инструкция «как исправить» для одной проверки */
export interface Recipe {
  checkId: string
  /** Варианты по стекам веб-сервера; у серверных проверок может быть пусто */
  stacks: Partial<Record<Stack, RecipeVariant>>
  /** Общий путь, когда стек не определён или не важен (для серверных проверок — основной) */
  generic: RecipeVariant
  /** Команда, которой пользователь сам убедится, что починил */
  verify: RecipeSnippet
  /** Чем рискует (HSTS preload почти необратим, CSP сначала Report-Only и т.п.); может быть пустым */
  risks: string[]
}

/** Значения плейсхолдеров в текстах и конфигах */
export interface RecipeVars {
  domain: string
  csp?: string
}
