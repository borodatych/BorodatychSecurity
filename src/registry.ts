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
import { opsCanary } from './checks/ops/canary'
import { opsMonitor } from './checks/ops/monitor'
import { webBanner } from './checks/web/banner'
import { webCookies } from './checks/web/cookies'
import { webCors } from './checks/web/cors'
import { webHeaders } from './checks/web/headers'
import { webRatelimit } from './checks/web/ratelimit'
import { webSecrets } from './checks/web/secrets'
import { webSourcemaps } from './checks/web/sourcemaps'
import { webTls } from './checks/web/tls'
import type { Check } from './types'

/** Все проверки разделов 1–6; раздел 5 работает только с --domain */
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
  webSecrets,
  webSourcemaps,
  webHeaders,
  webTls,
  webCors,
  webCookies,
  webRatelimit,
  webBanner,
  opsBackup,
  opsMonitor,
  opsCanary,
]
