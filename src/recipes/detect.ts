import type { Stack } from './types'

/** Определяет стеки по заголовкам ответа: сначала приложение, потом прокси */
export function detectStack(headers: Record<string, string>): Stack[] {
  const normalized = new Map<string, string>()
  for (const [key, value] of Object.entries(headers)) {
    normalized.set(key.toLowerCase(), value.toLowerCase())
  }

  const server = normalized.get('server') ?? ''
  const poweredBy = normalized.get('x-powered-by') ?? ''
  const hasNextHeader = [...normalized.keys()].some((key) => key.startsWith('x-nextjs-'))
  const result: Stack[] = []
  const add = (stack: Stack): void => {
    if (!result.includes(stack)) result.push(stack)
  }

  // Прикладной слой важнее прокси: рецепт приложения точнее
  if (poweredBy.includes('next.js') || poweredBy.includes('nextjs') || hasNextHeader) {
    add('nextjs')
  }
  if (poweredBy.includes('express')) add('express')

  if (normalized.has('cf-ray') || server.includes('cloudflare')) add('cloudflare')
  if (server.includes('openresty') || server.includes('nginx')) add('nginx')
  if (server.includes('caddy')) add('caddy')
  if (server.includes('apache')) add('apache')

  return result
}
