export interface CheckText {
  title: string
  problem: string
}

const fixes: Record<string, string> = {
  'common.sudo': 'запустите от root или с sudo для полной проверки',
  'common.none': 'ничего делать не нужно',
  'base.os': 'обновить выпуск до поддерживаемого',
  'base.autoupdates': 'поставить unattended-upgrades и включить только security-обновления',
  'base.pending': 'перезагрузить сервер и установить обновления безопасности',
  'base.livepatch': 'подключить Ubuntu Pro и Livepatch, для физлиц бесплатно до 5 машин',
  'ssh.auth': 'выключить пароли, root только по ключу или никак',
  'net.listen': 'слушать 127.0.0.1 или закрыть порт в сетевом экране',
  'net.docker-bypass': 'публиковать 127.0.0.1:порт:порт и закрыть в цепочке DOCKER-USER',
  'net.firewall': 'включить сетевой экран с запретом по умолчанию',
  'net.npm-admin': 'публиковать админку на 127.0.0.1, ходить через SSH-туннель',
  'docker.root': 'задать user, cap_drop: [ALL] и no-new-privileges',
  'docker.sock': 'убрать docker.sock или проксировать его только на чтение',
  'docker.mounts': 'монтировать только нужные каталоги, не корень и не /etc',
  'systemd.sandbox': 'добавить drop-in с CapabilityBoundingSet, ProtectSystem=strict и SystemCallFilter',
  'runtime.eol': 'обновить рантайм до поддерживаемой версии',
  'f2b.active': 'поставить fail2ban и включить джейл sshd',
  'f2b.docker': 'перевести баны в цепочку DOCKER-USER',
  crowdsec: 'поставить баунсер и подключить CAPI',
  'ops.backup': 'делать бэкап на другой хост и проверить восстановление',
  'ops.monitor': 'поставить Uptime Kuma или аналог на другой машине и оповещения в Telegram',
}

const checks: Record<string, CheckText> = {
  'base.os': {
    title: 'ОС с живой поддержкой',
    problem: 'срок поддержки истёк или истекает за 90 дней',
  },
  'base.autoupdates': {
    title: 'автообновления безопасности',
    problem: 'unattended-upgrades не стоит или выключен',
  },
  'base.pending': {
    title: 'висящие обновления безопасности и перезагрузка',
    problem: 'есть reboot-required старше 7 дней или не установлены security-обновления',
  },
  'base.livepatch': {
    title: 'Ubuntu Pro и Livepatch',
    problem: 'Ubuntu без Pro, ядро не получает обновления без перезагрузки',
  },
  'ssh.auth': {
    title: 'SSH только по ключам',
    problem: 'разрешены пароли, вход root или keyboard-interactive',
  },
  'net.listen': {
    title: 'что слушает на всех адресах',
    problem: 'на 0.0.0.0 или [::] слушает что-то кроме 22, 80 и 443',
  },
  'net.docker-bypass': {
    title: 'Docker публикует порт мимо UFW',
    problem: 'порт опубликован на все адреса при включённом UFW',
  },
  'net.firewall': {
    title: 'сетевой экран',
    problem: 'нет ни одного правила, политика ACCEPT',
  },
  'net.npm-admin': {
    title: 'админка Nginx Proxy Manager',
    problem: 'порт 81 опубликован на все адреса',
  },
  'docker.root': {
    title: 'контейнеры без root',
    problem: 'Privileged, root без cap_drop или без no-new-privileges',
  },
  'docker.sock': {
    title: 'docker.sock не проброшен',
    problem: 'в контейнер смонтирован /var/run/docker.sock',
  },
  'docker.mounts': {
    title: 'точечные тома',
    problem: 'в контейнер смонтированы /, /etc, /root или домашние каталоги целиком',
  },
  'systemd.sandbox': {
    title: 'песочница служб',
    problem: 'оценка systemd-analyze security выше 7',
  },
  'runtime.eol': {
    title: 'рантаймы без поддержки',
    problem: 'версия node, bun, php, python3 или PostgreSQL без поддержки',
  },
  'f2b.active': {
    title: 'Fail2ban',
    problem: 'fail2ban не стоит или нет джейла sshd',
  },
  'f2b.docker': {
    title: 'баны доходят до контейнеров',
    problem: 'баны попадают в INPUT, а порты контейнеров идут через FORWARD',
  },
  crowdsec: {
    title: 'CrowdSec и баунсер',
    problem: 'CrowdSec не стоит или стоит без баунсера либо без CAPI',
  },
  'ops.backup': {
    title: 'бэкап вне сервера',
    problem: 'бэкапа не нашли или он пишется только на этот же диск',
  },
  'ops.monitor': {
    title: 'внешний мониторинг',
    problem: 'изнутри сервера не проверить, нужен взгляд снаружи',
  },
}

const statusLabels: Record<string, string> = {
  ok: 'ок',
  warn: 'стоит поправить',
  fail: 'дыра',
  skip: 'неприменимо',
  unknown: 'не проверить',
}

const severityLabels: Record<string, string> = {
  critical: 'критично',
  high: 'высоко',
  medium: 'средне',
  low: 'низко',
}

const sectionTitles: Record<number, string> = {
  1: 'База',
  2: 'Что торчит наружу',
  3: 'Изоляция',
  4: 'Защита от перебора и ботов',
  5: 'Сайт снаружи',
  6: 'Хозяйство',
}

const report = {
  title: 'Borodatych Security',
  host: (host: string): string => `хост: ${host}`,
  startedAt: (iso: string): string => `начало: ${iso}`,
  summary: (counts: Record<string, number>): string =>
    `Итог: дыр ${String(counts.fail ?? 0)}, стоит поправить ${String(counts.warn ?? 0)}, ` +
    `не проверить ${String(counts.unknown ?? 0)}, неприменимо ${String(counts.skip ?? 0)}, ` +
    `ок ${String(counts.ok ?? 0)}`,
  worst: 'Худшие',
  fix: 'Чем чинить',
  problem: 'Что значит',
  noFindings: 'замечаний нет',
  noChecks: 'проверок не выбрано',
  error: (message: string): string => `Ошибка: ${message}`,
  hint: 'Запустите borodatych-security --help',
  unknownFixKey: 'описание исправления не найдено',
  help: [
    'borodatych-security — проверка защиты сервера, только чтение',
    '',
    'использование: borodatych-security [параметры]',
    '',
    '  --json              отчёт в JSON',
    '  --only id,id        выполнить только эти проверки',
    '  --skip id,id        пропустить эти проверки',
    '  --domain <host>     домен для будущих проверок сайта снаружи',
    '  --help, -h          эта справка',
    '  --version, -v       версия',
    '',
    'код выхода: 0 — нет fail, 1 — есть fail, 2 — ошибка CLI',
  ],
  version: (version: string): string => `borodatych-security ${version}`,
  fixLabel: (text: string): string => `Чем чинить: ${text}`,
  problemLabel: (text: string): string => `Что значит: ${text}`,
  finding: (text: string): string => `  - ${text}`,
  noChecksFor: (ids: string): string => `нет проверок для: ${ids}`,
}

const facts = {
  commandMissing: (cmd: string): string => `команда ${cmd} не найдена`,
  permissionDenied: (cmd: string): string => `нет прав на ${cmd}`,
  commandFailed: (cmd: string, detail: string): string =>
    detail.length > 0 ? `команда ${cmd} завершилась ошибкой: ${detail}` : `команда ${cmd} завершилась ошибкой`,
  timedOut: (cmd: string): string => `команда ${cmd} не успела за таймаут`,
  notLinux: (): string => 'не Linux, проверка неприменима',
  noDocker: (): string => 'Docker не найден, проверка неприменима',
  distro: (pretty: string): string => `система: ${pretty}`,
  supportUntil: (date: string, days: number): string => `поддержка до ${date}, осталось ${days} дн`,
  supportSoon: (date: string, days: number): string => `поддержка кончается ${date}, осталось ${days} дн`,
  supportExpired: (date: string): string => `поддержка закончилась ${date}`,
  supportUnknown: (key: string): string => `нет данных о сроках поддержки для ${key}`,
  enabled: (name: string): string => `${name}: включено`,
  disabled: (name: string): string => `${name}: выключено`,
  present: (name: string): string => `${name}: есть`,
  absent: (name: string): string => `${name}: нет`,
  rebootRequired: (days: number): string => `файл reboot-required есть ${days} дн`,
  rebootRequiredFresh: (days: number): string => `файл reboot-required есть ${days} дн, это меньше недели`,
  securityUpdates: (count: number): string => `security-обновлений: ${count}`,
  noSecurityUpdates: (): string => 'security-обновлений нет',
  setting: (key: string, value: string): string => `${key} ${value}`,
  listening: (address: string, port: number, process: string | null): string =>
    process === null ? `${address}:${port}` : `${address}:${port} ${process}`,
  containerPrivileged: (name: string): string => `${name}: privileged`,
  containerRoot: (name: string): string => `${name}: запущен от root`,
  containerNoCapDrop: (name: string): string => `${name}: нет cap_drop`,
  containerNoNewPrivileges: (name: string): string => `${name}: нет no-new-privileges`,
  containerSock: (name: string, known: boolean): string =>
    known ? `${name}: docker.sock, известное исключение` : `${name}: docker.sock`,
  containerMount: (name: string, source: string): string => `${name}: смонтирован ${source}`,
  containerPort: (name: string, hostIp: string, hostPort: number, containerPort: number): string =>
    `${name}: ${hostIp}:${hostPort} -> ${containerPort}`,
  serviceExposure: (unit: string, score: string): string => `${unit}: оценка ${score}`,
  jailAbsent: (name: string): string => `джейл ${name} не найден`,
  jailPresent: (name: string): string => `джейл ${name} есть`,
  fail2banAbsent: (): string => 'fail2ban-client не найден, fail2ban не стоит',
  ufwActive: (): string => 'ufw включён',
  ufwInactive: (): string => 'ufw выключен',
  iptablesRules: (count: number): string => `правил iptables: ${count}`,
  policy: (chain: string, policy: string): string => `политика ${chain}: ${policy}`,
  runtimeVersion: (name: string, version: string): string => `${name} ${version}`,
  runtimeEol: (name: string, version: string, until: string): string => `${name} ${version}: поддержка до ${until}`,
  runtimeUnknown: (name: string, version: string): string => `${name} ${version}: срок неизвестен, сверить`,
  runtimeAbsent: (name: string): string => `${name}: не найден`,
  proAbsent: (): string => 'pro status: Ubuntu Pro не подключён',
  proAttached: (): string => 'pro status: Ubuntu Pro подключён',
  livepatchOn: (): string => 'livepatch включён',
  livepatchOff: (): string => 'livepatch выключен',
  bouncerCount: (count: number): string => `баунсеров: ${count}`,
  bouncersNone: (): string => 'баунсеров нет',
  capiOn: (): string => 'CAPI подключён',
  capiOff: (): string => 'CAPI не подключён',
  cscliAbsent: (): string => 'cscli не найден, CrowdSec не стоит',
  backupFound: (command: string, remote: boolean): string =>
    remote ? `бэкап: ${command}, пишет наружу` : `бэкап: ${command}, только локально`,
  backupNone: (): string => 'заданий бэкапа не нашли',
  monitorOutside: (): string => 'проверка возможна только снаружи',
  domainAccepted: (domain: string): string => `домен принят для будущих проверок сайта: ${domain}`,
  noExposedPorts: (): string => 'на всех адресах только разрешённые порты',
  noContainers: (): string => 'запущенных контейнеров нет',
  noFirewall: (): string => 'сетевой экран не найден',
  configUnreadable: (path: string): string => `не удалось прочитать ${path}`,
  noConfig: (): string => 'настроек не нашли',
  noJails: (): string => 'джейлов нет',
  npmNotFound: (): string => 'Nginx Proxy Manager на порту 81 наружу не найден',
  nftRules: (): string => 'nftables: правила есть',
  f2bChain: (chain: string): string => `fail2ban chain: ${chain}`,
  f2bBanaction: (action: string): string => `fail2ban banaction: ${action}`,
}


/** Текст исправления по ключу из результата проверки */
export function fixText(key: string): string {
  return fixes[key] ?? report.unknownFixKey
}

export const ru = {
  status: statusLabels,
  severity: severityLabels,
  sections: sectionTitles,
  report,
  facts,
  checks,
  fixes,
}

export type Ru = typeof ru
