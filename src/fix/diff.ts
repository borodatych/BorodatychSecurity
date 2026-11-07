type OpType = 'equal' | 'add' | 'del'

interface Op {
  type: OpType
  text: string
}

interface Entry extends Op {
  oldNo: number | null
  newNo: number | null
}

const MAX_CELLS = 4_000_000
const CONTEXT = 3

function splitLines(text: string): string[] {
  const lines = text.split('\n')
  // Финальный перевод строки не считается отдельной строкой
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  return lines
}

function lcsOps(a: readonly string[], b: readonly string[]): Op[] {
  const n = a.length
  const m = b.length
  if (n === 0) return b.map((text) => ({ type: 'add', text }))
  if (m === 0) return a.map((text) => ({ type: 'del', text }))
  if (n * m > MAX_CELLS) {
    return [...a.map((text) => ({ type: 'del' as const, text })), ...b.map((text) => ({ type: 'add' as const, text }))]
  }

  const width = m + 1
  const dp = new Int32Array((n + 1) * width)
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i * width + j] =
        a[i] === b[j]
          ? (dp[(i + 1) * width + j + 1] ?? 0) + 1
          : Math.max(dp[(i + 1) * width + j] ?? 0, dp[i * width + j + 1] ?? 0)
    }
  }

  const ops: Op[] = []
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push({ type: 'equal', text: a[i] ?? '' })
      i += 1
      j += 1
    } else if ((dp[(i + 1) * width + j] ?? 0) >= (dp[i * width + j + 1] ?? 0)) {
      ops.push({ type: 'del', text: a[i] ?? '' })
      i += 1
    } else {
      ops.push({ type: 'add', text: b[j] ?? '' })
      j += 1
    }
  }
  while (i < n) {
    ops.push({ type: 'del', text: a[i] ?? '' })
    i += 1
  }
  while (j < m) {
    ops.push({ type: 'add', text: b[j] ?? '' })
    j += 1
  }
  return ops
}

/** Построчный diff без зависимостей: общий префикс и суффикс, затем LCS */
export function diffLines(before: string, after: string): Op[] {
  const a = splitLines(before)
  const b = splitLines(after)

  let start = 0
  while (start < a.length && start < b.length && a[start] === b[start]) start += 1
  let endA = a.length
  let endB = b.length
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA -= 1
    endB -= 1
  }

  const head: Op[] = a.slice(0, start).map((text) => ({ type: 'equal', text }))
  const middle = lcsOps(a.slice(start, endA), b.slice(start, endB))
  const tail: Op[] = a.slice(endA).map((text) => ({ type: 'equal', text }))
  return [...head, ...middle, ...tail]
}

function numbered(ops: readonly Op[]): Entry[] {
  const entries: Entry[] = []
  let oldNo = 1
  let newNo = 1
  for (const op of ops) {
    if (op.type === 'equal') {
      entries.push({ ...op, oldNo, newNo })
      oldNo += 1
      newNo += 1
    } else if (op.type === 'del') {
      entries.push({ ...op, oldNo, newNo: null })
      oldNo += 1
    } else {
      entries.push({ ...op, oldNo: null, newNo })
      newNo += 1
    }
  }
  return entries
}

function hunkHeader(oldStart: number, oldCount: number, newStart: number, newCount: number): string {
  return `@@ -${oldStart},${oldCount} +${newStart},${newCount} @@`
}

/** Unified diff: сначала общий заголовок файла, затем куски с контекстом */
export function unifiedDiff(path: string, before: string | null, after: string): string {
  const ops = before === null ? splitLines(after).map((text) => ({ type: 'add' as const, text })) : diffLines(before, after)
  const entries = numbered(ops)
  const changes: number[] = []
  for (let index = 0; index < entries.length; index += 1) {
    if (entries[index]?.type !== 'equal') changes.push(index)
  }
  if (changes.length === 0) return ''

  const oldPath = before === null ? '/dev/null' : `a${path.startsWith('/') ? path : `/${path}`}`
  const newPath = `b${path.startsWith('/') ? path : `/${path}`}`
  const lines = [`--- ${oldPath}`, `+++ ${newPath}`]

  let cursor = 0
  while (cursor < changes.length) {
    const first = changes[cursor] ?? 0
    let last = first
    cursor += 1
    while (
      cursor < changes.length &&
      (changes[cursor] ?? 0) - last <= CONTEXT * 2
    ) {
      last = changes[cursor] ?? last
      cursor += 1
    }

    const from = Math.max(0, first - CONTEXT)
    const to = Math.min(entries.length, last + CONTEXT + 1)
    const slice = entries.slice(from, to)
    if (slice.length === 0) continue

    const withOld = slice.filter((entry) => entry.oldNo !== null)
    const withNew = slice.filter((entry) => entry.newNo !== null)
    const oldStart = withOld[0]?.oldNo ?? (slice[0]?.oldNo ?? 0)
    const newStart = withNew[0]?.newNo ?? (slice[0]?.newNo ?? 0)
    lines.push(hunkHeader(oldStart, withOld.length, newStart, withNew.length))
    for (const entry of slice) {
      const prefix = entry.type === 'equal' ? ' ' : entry.type === 'add' ? '+' : '-'
      lines.push(`${prefix}${entry.text}`)
    }
  }

  return `${lines.join('\n')}\n`
}
