function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function asBoolean(value: unknown): boolean {
  return value === true
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

export interface DockerMount {
  type: string
  source: string
  destination: string
  readOnly: boolean
}

export interface DockerContainer {
  name: string
  image: string
  user: string
  privileged: boolean
  capAdd: string[]
  capDrop: string[]
  securityOpt: string[]
  mounts: DockerMount[]
}

function parseMount(value: unknown): DockerMount | null {
  const record = asRecord(value)
  if (record === null) return null
  return {
    type: asString(record.Type),
    source: asString(record.Source),
    destination: asString(record.Destination),
    readOnly: !asBoolean(record.RW),
  }
}

/** Разбор `docker inspect` (массив или один объект) */
export function parseDockerInspect(text: string): DockerContainer[] {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch {
    return []
  }
  const list = Array.isArray(data) ? data : [data]
  const containers: DockerContainer[] = []
  for (const item of list) {
    const record = asRecord(item)
    if (record === null) continue
    const config = asRecord(record.Config) ?? {}
    const host = asRecord(record.HostConfig) ?? {}
    const mounts = Array.isArray(record.Mounts)
      ? record.Mounts.map(parseMount).filter((mount): mount is DockerMount => mount !== null)
      : []
    containers.push({
      name: asString(record.Name).replace(/^\//, ''),
      image: asString(config.Image),
      user: asString(config.User),
      privileged: asBoolean(host.Privileged),
      capAdd: asStringArray(host.CapAdd),
      capDrop: asStringArray(host.CapDrop),
      securityOpt: asStringArray(host.SecurityOpt),
      mounts,
    })
  }
  return containers
}

export interface DockerPort {
  hostIp: string
  hostPort: number
  containerPort: number
  proto: string
}

export interface DockerPsEntry {
  name: string
  ports: DockerPort[]
}

function parsePortItem(item: string): DockerPort | null {
  const match = /^(.+):(\d+)->(\d+)\/(tcp|udp)$/.exec(item.trim())
  if (match === null) return null
  const hostIp = (match[1] ?? '').replace(/^\[/, '').replace(/\]$/, '')
  return {
    hostIp,
    hostPort: Number(match[2]),
    containerPort: Number(match[3]),
    proto: match[4] ?? '',
  }
}

/** Разбор `docker ps --format "{{.Names}}\t{{.Ports}}"` */
export function parseDockerPsPorts(text: string): DockerPsEntry[] {
  const entries: DockerPsEntry[] = []
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd()
    if (line.trim().length === 0) continue
    const tab = line.indexOf('\t')
    const name = tab >= 0 ? line.slice(0, tab) : line.split(/\s+/)[0] ?? ''
    const portsText = tab >= 0 ? line.slice(tab + 1) : ''
    const ports = portsText
      .split(',')
      .map(parsePortItem)
      .filter((port): port is DockerPort => port !== null)
    entries.push({ name, ports })
  }
  return entries
}
