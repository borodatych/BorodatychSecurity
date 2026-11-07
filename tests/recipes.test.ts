import { describe, expect, test } from 'bun:test'
import { audit } from '../src/audit'
import { webHeaders } from '../src/checks/web/headers'
import { recipes as en } from '../src/recipes/en'
import { recipes as ru } from '../src/recipes/ru'
import {
  buildCsp,
  collectResources,
  detectStack,
  getRecipe,
  pickVariant,
  renderRecipe,
} from '../src/recipes/index'
import type { Recipe, RecipeVariant, Stack } from '../src/recipes/types'
import { checks } from '../src/registry'

const IDS = checks.map((check) => check.id).sort()

function allVariants(recipe: Recipe): RecipeVariant[] {
  const list = [recipe.generic]
  for (const stack of Object.keys(recipe.stacks) as Stack[]) {
    const variant = recipe.stacks[stack]
    if (variant !== undefined) list.push(variant)
  }
  return list
}

function stringsOf(recipe: Recipe): string[] {
  const result: string[] = []
  for (const variant of allVariants(recipe)) {
    result.push(...variant.steps)
    if (variant.snippet !== undefined) result.push(variant.snippet.code)
  }
  result.push(recipe.verify.code, ...recipe.risks)
  return result
}

// %{ENV} в Apache — синтаксис конфига, а не наш плейсхолдер
const PLACEHOLDER = /(?<!\{)(?<!%)\{[A-Za-z][A-Za-z0-9_]*\}(?!\})/g

describe('полнота рецептов', () => {
  test('у каждой проверки есть рецепт в ru и en', () => {
    expect(Object.keys(ru).sort()).toEqual(IDS)
    expect(Object.keys(en).sort()).toEqual(IDS)
    for (const id of IDS) {
      expect(ru[id]?.checkId).toBe(id)
      expect(en[id]?.checkId).toBe(id)
    }
  })

  test('наборы стеков в ru и en совпадают', () => {
    for (const id of IDS) {
      const ruStacks = Object.keys(ru[id]?.stacks ?? {}).sort()
      const enStacks = Object.keys(en[id]?.stacks ?? {}).sort()
      expect(ruStacks).toEqual(enStacks)
    }
  })

  test('ни один шаг, код и риск не пустые', () => {
    for (const locale of ['ru', 'en'] as const) {
      const source = locale === 'ru' ? ru : en
      for (const id of IDS) {
        const recipe = source[id]
        if (recipe === undefined) throw new Error(`нет рецепта ${id}`)
        expect(recipe.generic.steps.length).toBeGreaterThan(0)
        expect(recipe.verify.code.trim().length).toBeGreaterThan(0)
        for (const risk of recipe.risks) expect(risk.trim().length).toBeGreaterThan(0)
        for (const variant of allVariants(recipe)) {
          expect(variant.steps.length).toBeGreaterThan(0)
          for (const step of variant.steps) expect(step.trim().length).toBeGreaterThan(0)
          if (variant.snippet !== undefined) {
            expect(variant.snippet.code.trim().length).toBeGreaterThan(0)
          }
        }
      }
    }
  })
})

describe('renderRecipe', () => {
  test('плейсхолдеры из списка не остаются', () => {
    for (const locale of ['ru', 'en'] as const) {
      for (const id of IDS) {
        const recipe = getRecipe(id, locale)
        if (recipe === null) throw new Error(`нет рецепта ${id}`)
        const text = JSON.stringify(renderRecipe(recipe, { domain: 'example.ru' }))
        expect(text).not.toContain('{domain}')
        expect(text).not.toContain('{csp}')
      }
    }
  })

  test('неизвестных плейсхолдеров в данных нет', () => {
    for (const locale of ['ru', 'en'] as const) {
      const source = locale === 'ru' ? ru : en
      for (const id of IDS) {
        const recipe = source[id]
        if (recipe === undefined) throw new Error(`нет рецепта ${id}`)
        for (const text of stringsOf(recipe)) {
          for (const match of text.match(PLACEHOLDER) ?? []) {
            expect(['{domain}', '{csp}']).toContain(match)
          }
        }
      }
    }
  })

  test('csp по умолчанию безопасный стартовый', () => {
    const recipe = getRecipe('web.headers')
    if (recipe === null) throw new Error('нет рецепта web.headers')
    const rendered = renderRecipe(recipe, { domain: 'example.ru' })
    expect(rendered.generic.steps.join(' ')).toContain('Report-Only')
    expect(JSON.stringify(rendered)).toContain(
      "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    )
  })

  test('свой csp подставляется, исходный рецепт не меняется', () => {
    const recipe = getRecipe('web.headers')
    if (recipe === null) throw new Error('нет рецепта web.headers')
    const before = JSON.stringify(recipe)
    const rendered = renderRecipe(recipe, { domain: 'example.ru', csp: "default-src 'none'" })
    expect(JSON.stringify(rendered)).toContain('default-src \'none\'')
    expect(JSON.stringify(recipe)).toBe(before)
  })

  test('getRecipe: неизвестный id — null', () => {
    expect(getRecipe('no.such')).toBeNull()
    expect(getRecipe('ssh.auth', 'en')?.checkId).toBe('ssh.auth')
  })
})

describe('detectStack', () => {
  const cases: { headers: Record<string, string>; expected: Stack[] }[] = [
    { headers: { server: 'nginx/1.24.0' }, expected: ['nginx'] },
    { headers: { server: 'cloudflare', 'cf-ray': 'abc' }, expected: ['cloudflare'] },
    { headers: { server: 'nginx', 'x-powered-by': 'Express' }, expected: ['express', 'nginx'] },
    { headers: { 'x-powered-by': 'Next.js', 'x-nextjs-cache': 'HIT' }, expected: ['nextjs'] },
    { headers: { server: 'Apache/2.4.58 (Ubuntu)' }, expected: ['apache'] },
    { headers: { server: 'Caddy' }, expected: ['caddy'] },
    { headers: { server: 'openresty/1.21.4.1' }, expected: ['nginx'] },
    { headers: { Server: 'nginx', 'X-Powered-By': 'Express' }, expected: ['express', 'nginx'] },
    { headers: {}, expected: [] },
  ]
  for (const item of cases) {
    test(JSON.stringify(item.headers), () => {
      expect(detectStack(item.headers)).toEqual(item.expected)
    })
  }

  test('без дублей', () => {
    const stacks = detectStack({ server: 'cloudflare', 'cf-ray': 'x' })
    expect(new Set(stacks).size).toBe(stacks.length)
  })
})

describe('collectResources и buildCsp', () => {
  const html = `<!doctype html>
<html>
  <head>
    <link rel="stylesheet" href="/app.css">
    <link rel="preload" as="font" href="https://fonts.gstatic.com/s/inter.woff2">
    <script src="https://cdn.example.net/lib.js"></script>
    <script>console.log('inline')</script>
    <style>.a { color: red }</style>
  </head>
  <body>
    <img src="/logo.png" srcset="https://cdn.example.net/a.png 1x, /b.png 2x">
    <img src="data:image/png;base64,AAA">
    <iframe src="https://player.example.org/v"></iframe>
    <form action="/search"></form>
  </body>
</html>`

  const res = collectResources(html, 'https://example.ru/')

  test('скрипты, шрифты, картинки и формы сводятся к origin', () => {
    expect(res.script).toEqual(['https://cdn.example.net'])
    expect(res.style).toEqual(['self'])
    expect(res.font).toEqual(['https://fonts.gstatic.com'])
    expect(res.img).toEqual(['data:', 'https://cdn.example.net', 'self'])
    expect(res.frame).toEqual(['https://player.example.org'])
    expect(res.form).toEqual(['self'])
    expect(res.inlineScript).toBe(true)
    expect(res.inlineStyle).toBe(true)
  })

  test('CSP собирается по ресурсам, inline-стиль даёт unsafe-inline', () => {
    const csp = buildCsp(res)
    expect(csp).toContain("default-src 'self'")
    expect(csp).toContain("script-src 'self' https://cdn.example.net")
    expect(csp).toContain("style-src 'self' 'unsafe-inline'")
    expect(csp).toContain("img-src 'self' data: https://cdn.example.net")
    expect(csp).toContain("font-src 'self' https://fonts.gstatic.com")
    expect(csp).toContain("frame-src 'self' https://player.example.org")
    expect(csp).toContain("form-action 'self'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).toContain("base-uri 'self'")
    expect(csp).toContain("frame-ancestors 'self'")
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'")
  })
})

describe('pickVariant', () => {
  test('первый известный стек, иначе общий путь', () => {
    const recipe = getRecipe('web.headers')
    if (recipe === null) throw new Error('нет рецепта web.headers')
    expect(pickVariant(recipe, ['express', 'nginx']).stack).toBe('express')
    expect(pickVariant(recipe, ['nginx', 'express']).stack).toBe('nginx')
    expect(pickVariant(recipe, ['traefik']).stack).toBe('traefik')
    expect(pickVariant(recipe, []).stack).toBeNull()
  })
})

describe('audit: site в отчёте', () => {
  test('стеки и CSP главной заполняются из ответа сессии', async () => {
    const html =
      '<!doctype html><html><head><script src="https://cdn.example.net/lib.js"></script></head><body></body></html>'
    let calls = 0
    const fakeFetch = (() => {
      calls += 1
      return Promise.resolve(
        new Response(html, {
          status: 200,
          headers: {
            'content-type': 'text/html',
            server: 'nginx',
            'x-powered-by': 'Express',
          },
        }),
      )
    }) as unknown as typeof fetch

    const report = await audit([webHeaders], {
      domain: 'example.ru',
      fetch: fakeFetch,
      host: 'test',
    })
    expect(report.site).toBeDefined()
    expect(report.site?.stacks).toEqual(['express', 'nginx'])
    expect(report.site?.csp).toContain("script-src 'self' https://cdn.example.net")
    expect(calls).toBe(1)
  })

  test('без раздела 5 site не заполняется', async () => {
    const report = await audit([], { domain: 'example.ru', host: 'test' })
    expect(report.site).toBeUndefined()
  })
})
