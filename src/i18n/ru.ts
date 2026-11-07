export interface CheckText {
  title: string
  problem: string
}

const fixes: Record<string, string> = {
  'common.sudo': 'запустите от root или с sudo для полной проверки',
  'common.none': 'ничего делать не нужно',
  'common.network': 'проверьте сеть и доступность домена',
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
  'web.secrets': 'закрыть в прокси, отдавать 404 или 444',
  'web.sourcemaps': 'не публиковать карты исходников',
  'web.headers': 'выставить HSTS, nosniff, frame-ancestors, Referrer-Policy и CSP',
  'web.tls': 'продлить сертификат и выключить TLS 1.0/1.1',
  'web.cors': 'разрешить только свои источники',
  'web.cookies': 'выставить Secure, HttpOnly и SameSite',
  'web.ratelimit': 'включить лимит запросов на прокси',
  'web.banner': 'убрать версии из заголовков',
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
  'web.secrets': {
    title: 'утечки по известным адресам',
    problem: 'по известным путям отдаётся настоящее содержимое',
  },
  'web.sourcemaps': {
    title: 'карты исходников',
    problem: 'карта исходников отдаётся',
  },
  'web.headers': {
    title: 'заголовки безопасности',
    problem: 'нет HSTS, nosniff, защиты от встраивания, Referrer-Policy или CSP',
  },
  'web.tls': {
    title: 'сертификат и протоколы',
    problem: 'сертификат истекает или принимаются TLS 1.0/1.1',
  },
  'web.cors': {
    title: 'CORS',
    problem: 'чужой Origin допускается вместе с credentials',
  },
  'web.cookies': {
    title: 'флаги cookie',
    problem: 'сессионная cookie без Secure, HttpOnly или SameSite',
  },
  'web.ratelimit': {
    title: 'лимит запросов',
    problem: 'на 30 быстрых запросов ни одного 429',
  },
  'web.banner': {
    title: 'версии ПО в ответах',
    problem: 'Server или X-Powered-By показывает версию',
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

/** Колонка «как» из docs/checks.md: сверяется тестом, чтобы справка не расходилась с документом */
const checksHow: Record<string, string> = {
  'base.os': '`/etc/os-release` + встроенная таблица сроков поддержки Ubuntu и Debian',
  'base.autoupdates':
    'Debian/Ubuntu: пакет и таймер `unattended-upgrades`, `/etc/apt/apt.conf.d/20auto-upgrades`',
  'base.pending': '`/var/run/reboot-required`, число security-обновлений (`apt-get -s upgrade`)',
  'base.livepatch': '`pro status`',
  'ssh.auth': '`sshd -T` (или конфиг)',
  'net.listen': '`ss -ltnup`',
  'net.docker-bypass': '`docker ps` с портами `0.0.0.0:` + включён ли UFW',
  'net.firewall': 'ufw/nftables/iptables',
  'net.npm-admin': 'контейнер NPM и порт 81',
  'docker.root': '`docker inspect` User, Privileged, CapAdd, SecurityOpt',
  'docker.sock': '`docker inspect` Mounts',
  'docker.mounts': 'Mounts',
  'systemd.sandbox': '`systemd-analyze security` для служб, которые слушают порты',
  'runtime.eol': 'версии `node`, `bun`, `php`, `python3`, PostgreSQL, образы в `docker ps`',
  'f2b.active': '`fail2ban-client status`',
  'f2b.docker': 'при Docker: `banaction` и цепочка DOCKER-USER',
  crowdsec: '`cscli` версии, `cscli bouncers list`, `cscli capi status`',
  'web.secrets':
    'GET `/.env`, `/.git/config`, `/.git/HEAD`, `/config.json`, `/.DS_Store`, `/backup.sql`, `/server-status`, `/phpinfo.php`',
  'web.sourcemaps': 'ссылки `sourceMappingURL` в JS главной и GET на них',
  'web.headers': 'ответ главной',
  'web.tls': 'TLS-рукопожатие',
  'web.cors': 'OPTIONS и GET с чужим Origin',
  'web.cookies': 'Set-Cookie главной',
  'web.ratelimit': '30 быстрых запросов к главной',
  'web.banner': '`Server`, `X-Powered-By`',
  'ops.backup': 'таймеры и cron с `pg_dump`, `restic`, `borg`, `rclone`; куда пишут',
  'ops.monitor': 'не проверить изнутри — всегда `unknown` с подсказкой',
}

const mcp = {
  unknownCheck: (id: string, known: string): string =>
    `неизвестная проверка: ${id}. Известные: ${known}`,
  auditFailed: (message: string): string => `проверка не выполнена: ${message}`,
  invalidDomain: (reason: string): string => `домен не принят: ${reason}`,
  domainEmpty: 'пустая строка',
  domainTooLong: 'длиннее 253 символов',
  domainSpace: 'есть пробелы',
  domainScheme: 'указана схема, нужно только имя хоста',
  domainPath: 'указан путь, параметры или якорь, нужно только имя хоста',
  domainPort: 'указан порт или IPv6, нужно только имя хоста',
  domainIp: 'IP-адреса запрещены, нужен домен',
  domainFormat: 'не похоже на имя хоста',
  invalidList: (name: string): string => `${name}: ожидается массив непустых строк`,
  invalidBoolean: (name: string): string => `${name}: ожидается true или false`,
  invalidId: 'id: ожидается непустая строка',
  invalidArgument: (name: string): string => `${name}: неожиданный тип аргумента`,
  noArgs: 'подкоманда mcp не принимает аргументов',
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
  promo: 'Слежение за сайтом и история проверок — https://security.borodatych.ru',
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
    '  --domain <host>     домен для проверок сайта снаружи (раздел 5)',
    '  --quiet             не печатать строку про сайт в конце отчёта',
    '  mcp                 MCP-сервер по stdio для агентов (только чтение)',
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
  backupRemote: (source: string, command: string): string =>
    `${source}: ${command} — пишет наружу, восстановление не проверено`,
  backupLocal: (source: string, command: string): string =>
    `${source}: ${command} — только локально`,
  backupUnknown: (source: string, command: string): string =>
    `${source}: ${command} — куда пишет, не определить, проверьте руками`,
  backupNone: (): string => 'заданий бэкапа не нашли',
  firewallOnlyAllowed: (): string =>
    'сетевой экран не найден, на всех адресах только 22, 80 и 443 — включить вторым слоем',
  noListeningServices: (): string => 'служб, которые слушают порты, не нашли',
  unitsUnknown: (): string => 'не удалось определить юниты слушающих процессов',
  sshNotEvaluated: (): string => 'ssh не оценивается: его высокая оценка — норма',
  webNoDomain: (): string => 'домен не задан (--domain), проверка сайта снаружи неприменима',
  webRequestFailed: (what: string, detail: string): string =>
    `запрос ${what} не удался: ${detail}`,
  webSecretsNone: (): string => 'утечек по известным адресам нет',
  webSecretLeak: (path: string): string => `по ${path} отдаётся настоящее содержимое`,
  webSourceMapsNone: (): string => 'карт исходников не нашли',
  webSourceMapLeak: (url: string): string => `карта исходников отдаётся: ${url}`,
  webHeaderMissing: (name: string): string => `нет ${name}`,
  webHeadersOk: (): string => 'заголовки безопасности на месте',
  webCertDays: (days: number): string => `сертификат действует ещё ${days} дн`,
  webCertSoon: (days: number): string => `сертификат истекает через ${days} дн`,
  webCertExpired: (days: number): string => `сертификат истёк ${days} дн назад`,
  webLegacyTlsAccepted: (): string => 'TLS 1.0/1.1 принимаются',
  webLegacyTlsRefused: (): string => 'TLS 1.0/1.1 отклоняются',
  webTlsFailed: (detail: string): string => `TLS-рукопожатие не удалось: ${detail}`,
  webCorsOk: (): string => 'CORS не открыт для чужих источников',
  webCorsOpen: (origin: string, credentials: boolean): string =>
    credentials
      ? `CORS: ${origin} допускается вместе с credentials`
      : `CORS: ${origin} открыт для чужих источников`,
  webCookiesNone: (): string => 'cookie на главной не ставятся',
  webCookiesOk: (): string => 'флаги сессионных cookie на месте',
  webCookieBad: (name: string, missing: string): string => `cookie ${name}: нет ${missing}`,
  webRateLimitHit: (count: number, total: number): string =>
    `ответов 429: ${count} из ${total}`,
  webRateLimitNone: (total: number): string => `на ${total} быстрых запросов ни одного 429`,
  webBannerNone: (): string => 'версий в заголовках нет',
  webBannerVersion: (header: string, value: string): string => `${header}: ${value}`,
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
  how: checksHow,
  fixes,
  mcp,
}

export type Ru = typeof ru
