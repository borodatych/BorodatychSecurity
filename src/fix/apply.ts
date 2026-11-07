import { dirname, posix } from 'node:path'
import { ru } from '../i18n/ru'
import { CADDYFILE_PATH } from './caddy'
import type {
  BackupFile,
  BackupManifest,
  FixCtx,
  FixPlan,
  FixServer,
  FileInfo,
} from './types'

export interface ApplyResult {
  ok: boolean
  backupDir: string
  manifest: BackupManifest | null
  error: string | null
}

function cleanPath(path: string): string {
  return path
    .split('/')
    .filter((part) => part.length > 0 && part !== '..' && part !== '.')
    .join('/')
}

/** Полный путь копии внутри каталога бэкапа */
export function backupFilePath(root: string, original: string): string {
  return posix.join(root.replace(/\/+$/, ''), cleanPath(original))
}

function tmpPath(path: string): string {
  return `${path}.borodatych-security.tmp`
}

async function writeAtomic(
  ctx: FixCtx,
  path: string,
  content: string,
  info: FileInfo | null,
): Promise<void> {
  await ctx.mkdir(dirname(path), 0o755)
  const tmp = tmpPath(path)
  await ctx.write(tmp, content)
  if (info !== null) {
    await ctx.chmod(tmp, info.mode)
    await ctx.chown(tmp, info.uid, info.gid)
  }
  await ctx.rename(tmp, path)
}

function resultText(result: { stdout: string; stderr: string }): string {
  return (result.stderr.trim() || result.stdout.trim()).slice(0, 2000)
}

/** Проверка конфига до перезагрузки */
export async function validateConfig(
  ctx: FixCtx,
  server: FixServer,
): Promise<{ ok: boolean; detail: string }> {
  const result =
    server === 'nginx'
      ? await ctx.run('nginx', ['-t'])
      : await ctx.run('caddy', ['validate', '--config', CADDYFILE_PATH, '--adapter', 'caddyfile'])
  return { ok: result.ok, detail: resultText(result) }
}

/** Перезагрузка службы; если systemctl нет — прямая команда сервера */
export async function reloadServer(
  ctx: FixCtx,
  server: FixServer,
): Promise<{ ok: boolean; detail: string }> {
  const unit = server === 'nginx' ? 'nginx' : 'caddy'
  const systemctl = await ctx.run('systemctl', ['reload', unit])
  if (systemctl.ok) return { ok: true, detail: '' }
  if (systemctl.reason !== 'missing') return { ok: false, detail: resultText(systemctl) }

  const direct =
    server === 'nginx'
      ? await ctx.run('nginx', ['-s', 'reload'])
      : await ctx.run('caddy', ['reload', '--config', CADDYFILE_PATH, '--adapter', 'caddyfile'])
  return { ok: direct.ok, detail: resultText(direct) }
}

/** Вернуть все файлы из бэкапа и удалить созданные нами */
export async function restoreManifest(
  ctx: FixCtx,
  backupDir: string,
  manifest: BackupManifest,
): Promise<void> {
  for (const file of manifest.files) {
    const content = await ctx.read(posix.join(backupDir, file.backup))
    if (content === null) throw new Error(ru.fix.backupMissing(file.backup))
    const info: FileInfo | null =
      file.mode === null
        ? null
        : {
            mode: file.mode,
            uid: file.uid ?? 0,
            gid: file.gid ?? 0,
          }
    await writeAtomic(ctx, file.path, content, info)
  }
  for (const path of manifest.created) {
    if (await ctx.exists(path)) await ctx.remove(path)
  }
}

function parseManifest(text: string): BackupManifest | null {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return null
  }
  if (typeof value !== 'object' || value === null) return null
  const record = value as Record<string, unknown>
  if (record.version !== 1) return null
  if (typeof record.createdAt !== 'string' || typeof record.domain !== 'string') return null
  if (record.server !== 'nginx' && record.server !== 'caddy') return null
  if (!Array.isArray(record.files) || !Array.isArray(record.created)) return null
  const files: BackupFile[] = []
  for (const item of record.files) {
    if (typeof item !== 'object' || item === null) return null
    const file = item as Record<string, unknown>
    if (typeof file.path !== 'string' || typeof file.backup !== 'string') return null
    files.push({
      path: file.path,
      backup: file.backup,
      mode: typeof file.mode === 'number' ? file.mode : null,
      uid: typeof file.uid === 'number' ? file.uid : null,
      gid: typeof file.gid === 'number' ? file.gid : null,
    })
  }
  const created = record.created.filter((item): item is string => typeof item === 'string')
  if (created.length !== record.created.length) return null
  return {
    version: 1,
    createdAt: record.createdAt,
    domain: record.domain,
    server: record.server,
    files,
    created,
    rollbackCommand:
      typeof record.rollbackCommand === 'string' ? record.rollbackCommand : '',
  }
}

export async function readManifest(
  ctx: FixCtx,
  backupDir: string,
): Promise<BackupManifest | null> {
  const text = await ctx.read(posix.join(backupDir, 'manifest.json'))
  return text === null ? null : parseManifest(text)
}

/** Бэкап, атомарная запись, проверка конфига и перезагрузка с откатом */
export async function applyPlan(
  ctx: FixCtx,
  plan: FixPlan,
  server: FixServer,
  backupDir: string,
): Promise<ApplyResult> {
  const manifest: BackupManifest = {
    version: 1,
    createdAt: ctx.now.toISOString(),
    domain: plan.domain,
    server,
    files: [],
    created: [],
    rollbackCommand: ru.fix.rollbackCommand(backupDir),
  }
  const infos = new Map<string, FileInfo | null>()

  try {
    await ctx.mkdir(backupDir, 0o700)
  } catch (error) {
    return { ok: false, backupDir, manifest: null, error: messageOf(error) }
  }

  try {
    for (const edit of plan.edits) {
      const info = edit.before === null ? null : await ctx.stat(edit.path)
      infos.set(edit.path, info)
      if (edit.before === null) {
        manifest.created.push(edit.path)
        continue
      }
      const backup = posix.join(backupDir, cleanPath(edit.path))
      await ctx.mkdir(dirname(backup), 0o700)
      await ctx.write(backup, edit.before)
      await ctx.chmod(backup, 0o600)
      manifest.files.push({
        path: edit.path,
        backup: cleanPath(edit.path),
        mode: info?.mode ?? null,
        uid: info?.uid ?? null,
        gid: info?.gid ?? null,
      })
    }
    await ctx.write(posix.join(backupDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
    await ctx.chmod(posix.join(backupDir, 'manifest.json'), 0o600)
  } catch (error) {
    // Бэкап неполный: восстанавливаем то, что успели записать
    try {
      await restoreManifest(ctx, backupDir, manifest)
    } catch {
      // восстановление уже нечего добавить к исходной ошибке
    }
    return { ok: false, backupDir, manifest, error: messageOf(error) }
  }

  try {
    for (const edit of plan.edits) {
      await writeAtomic(ctx, edit.path, edit.after, infos.get(edit.path) ?? null)
    }
  } catch (error) {
    await safeRestore(ctx, backupDir, manifest)
    return { ok: false, backupDir, manifest, error: messageOf(error) }
  }

  const validation = await validateConfig(ctx, server)
  if (!validation.ok) {
    await safeRestore(ctx, backupDir, manifest)
    return { ok: false, backupDir, manifest, error: ru.fix.validateFailed(validation.detail) }
  }

  const reload = await reloadServer(ctx, server)
  if (!reload.ok) {
    await safeRestore(ctx, backupDir, manifest)
    await reloadServer(ctx, server)
    return { ok: false, backupDir, manifest, error: ru.fix.reloadFailed(reload.detail) }
  }

  return { ok: true, backupDir, manifest, error: null }
}

async function safeRestore(ctx: FixCtx, backupDir: string, manifest: BackupManifest): Promise<void> {
  try {
    await restoreManifest(ctx, backupDir, manifest)
  } catch {
    // откат не удался: текст ошибки уже напечатан вызывающим
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Откат по манифесту: файлы из бэкапа, удаление созданных, проверка и reload */
export async function rollback(
  ctx: FixCtx,
  backupDir: string,
): Promise<{ ok: boolean; error: string | null; manifest: BackupManifest | null }> {
  const manifest = await readManifest(ctx, backupDir)
  if (manifest === null) {
    return { ok: false, error: ru.fix.manifestMissing(backupDir), manifest: null }
  }

  try {
    await restoreManifest(ctx, backupDir, manifest)
  } catch (error) {
    return { ok: false, error: messageOf(error), manifest }
  }

  const validation = await validateConfig(ctx, manifest.server)
  if (!validation.ok) {
    return { ok: false, error: ru.fix.rollbackValidateFailed(validation.detail), manifest }
  }
  const reload = await reloadServer(ctx, manifest.server)
  if (!reload.ok) {
    return { ok: false, error: ru.fix.reloadFailed(reload.detail), manifest }
  }
  return { ok: true, error: null, manifest }
}
