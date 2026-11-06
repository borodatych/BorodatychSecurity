import { f2bActive } from './checks/antibot/f2b-active'
import { f2bDocker } from './checks/antibot/f2b-docker'
import { crowdsec } from './checks/antibot/crowdsec'
import { baseAutoupdates } from './checks/base/autoupdates'
import { baseLivepatch } from './checks/base/livepatch'
import { baseOs } from './checks/base/os'
import { basePending } from './checks/base/pending'
import { sshAuth } from './checks/base/ssh-auth'
import { dockerMounts } from './checks/isolation/docker-mounts'
import { dockerRoot } from './checks/isolation/docker-root'
import { dockerSock } from './checks/isolation/docker-sock'
import { runtimeEol } from './checks/isolation/runtime-eol'
import { systemdSandbox } from './checks/isolation/systemd-sandbox'
import { netDockerBypass } from './checks/net/docker-bypass'
import { netFirewall } from './checks/net/firewall'
import { netListen } from './checks/net/listen'
import { netNpmAdmin } from './checks/net/npm-admin'
import { opsBackup } from './checks/ops/backup'
import { opsMonitor } from './checks/ops/monitor'
import type { Check } from './types'

/** Все проверки разделов 1–4 и 6; раздел 5 и MCP появятся отдельной задачей */
export const checks: Check[] = [
  baseOs,
  baseAutoupdates,
  basePending,
  baseLivepatch,
  sshAuth,
  netListen,
  netDockerBypass,
  netFirewall,
  netNpmAdmin,
  dockerRoot,
  dockerSock,
  dockerMounts,
  systemdSandbox,
  runtimeEol,
  f2bActive,
  f2bDocker,
  crowdsec,
  opsBackup,
  opsMonitor,
]
