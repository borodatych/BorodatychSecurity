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
  'ops.canary': 'разложить приманки Canarytokens (AWS API Keys) с правами 600 и проверить доставку писем',
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
    problem: 'CrowdSec не стоит, стоит без живого баунсера либо без CAPI',
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
  'ops.canary': {
    title: 'датчик проникновения',
    problem: 'нет приманки или она открыта: вора, который уже внутри, никто не заметит',
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
  crowdsec: '`cscli` версии, `cscli bouncers list -o json` (дата последнего pull), `cscli capi status`',
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
  'ops.canary': 'пути из `--canary`: `stat` прав и владельца, содержимое не читается; без путей — `unknown` с подсказкой',
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
  serverCheck: (id: string): string =>
    `серверные проверки — audit_server на самом сервере: ${id} здесь не проверяется`,
  invalidStack: (name: string, known: string): string =>
    `стек не принят: ${name}. Известные: ${known}`,
}

const account = {
  loginRequired: 'Войдите: npx @borodatych/security login',
  tokenInvalid: 'Токен отозван или неверен, войдите заново',
  noFreeSlots: (limit: number | null, apiBase: string): string =>
    `Бесплатные домены закончились${limit === null ? '' : ` (${limit} из ${limit})`}. Доступ на домен — в кабинете: ${apiBase}/my/checks`,
  loginCode: (code: string): string => `Код: ${code}`,
  loginUrl: (url: string): string => `Откройте ссылку: ${url}`,
  loginWaiting: 'Ждём подтверждения в браузере',
  loginDenied: 'Вход отклонён в браузере',
  loginExpired: 'Код истёк, запустите login заново',
  greeting: (email: string): string => `Вошли как ${email}`,
  logoutDone: 'Токен удалён',
  logoutNone: 'Сохранённого токена нет',
  whoamiEmail: (email: string): string => `Вы: ${email}`,
  whoamiFree: (left: number, limit: number): string =>
    `Бесплатных доменов осталось: ${left} из ${limit}`,
  whoamiAccess: 'Домены с доступом:',
  whoamiNoAccess: 'Доменов с доступом нет',
  whoamiFreeSite: (domain: string, since: string): string =>
    `  - ${domain} (бесплатный слот с ${since})`,
  whoamiPass: (domain: string, until: string): string => `  - ${domain} (пропуск до ${until})`,
  rateLimited: (retryAfter: number | null): string =>
    retryAfter === null
      ? 'Сервис просит подождать: слишком много запросов'
      : `Сервис просит подождать ${retryAfter} с: слишком много запросов`,
  network: (detail: string): string => `Сервис недоступен: ${detail}`,
  serverError: (status: number): string => `Сервис ответил ошибкой: HTTP ${status}`,
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
    '  --canary путь,путь  файлы-приманки для проверки ops.canary',
    '  --quiet             не печатать строку про сайт в конце отчёта',
    '  mcp                 MCP-сервер по stdio для агентов (только чтение)',
    '  fix                 починить сайт на сервере (единственная команда, которая меняет сервер)',
    '  login               войти через браузер и сохранить токен',
    '  logout              удалить сохранённый токен',
    '  whoami [--json]     кто вошёл и какие домены открыты',
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
  bouncerAlive: (name: string, at: string): string => `баунсер ${name}: забирал решения ${at}`,
  bouncerStale: (name: string, at: string, hours: number): string =>
    `баунсер ${name}: последний pull ${at}, дольше ${hours} ч — решения до сетевого экрана не доходят`,
  bouncerNeverPulled: (name: string): string => `баунсер ${name}: ни разу не забирал решения`,
  bouncerRevoked: (name: string): string => `баунсер ${name}: ключ отозван`,
  bouncersUnparsed: (): string => 'не удалось разобрать cscli bouncers list -o json',
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
  webCspReportOnly: (): string =>
    'CSP только в режиме Report-Only: после недели без нарушений переименуйте заголовок в Content-Security-Policy',
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
  canaryNotConfigured: (): string =>
    'приманки не заданы (--canary <путь>): изнутри не узнать, есть ли датчик проникновения',
  canaryAbsent: (path: string): string => `приманки ${path} нет`,
  canaryOpen: (path: string, mode: string, owner: string): string =>
    `приманка ${path}: права ${mode}, владелец ${owner} — нужно 600 и root:root`,
  canaryOk: (path: string): string => `приманка ${path} на месте, права 600, root:root`,
  canaryUnchecked: (path: string): string => `приманку ${path} не проверить: нет прав или stat`,
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

const fix = {
  itemName: (id: string): string => {
    if (id === 'web.headers') return 'заголовки безопасности'
    if (id === 'web.banner') return 'версия сервера в ответах'
    if (id === 'web.sourcemaps') return 'карты исходников'
    if (id === 'web.ratelimit') return 'лимит запросов'
    return id
  },
  alreadyManual: (name: string): string => `${name}: уже задано вручную, не трогаю`,
  noServerBlock: (domain: string): string =>
    `server-блок с ${domain} не найден, файл не трогаю`,
  noServerName: 'в server-блоке нет server_name, вставить include некуда',
  noConfD: 'в http нет include conf.d/*.conf, зону лимита некуда положить',
  foreignFile: (path: string): string =>
    `${path} уже есть и создан не нами, файл не трогаю`,
  foreignSnippet: (name: string): string =>
    `сниппет (${name}) уже есть без нашего маркера, не трогаю`,
  snippetBlocked: 'сниппет занят чужим файлом, зону лимита не создаю',
  caddyRatelimit: 'Caddy: лимит запросов настраивается вручную, показываю рецепт',
  summarySnippet: 'сниппет borodatych-security.conf с директивами уровня server',
  summaryInclude: 'include сниппета после server_name',
  summaryRatelimit: 'зона limit_req_zone в conf.d',
  summarySnippetCaddy: 'сниппет (borodatych-security) в Caddyfile',
  summaryCaddy: 'сниппет и import в блоках сайта',
  notLinux: 'fix работает только на Linux',
  needRoot: 'нужен root: запустите через sudo',
  domainRequired: 'укажите домен: fix --domain example.ru',
  domainInvalid: (reason: string): string => `домен не принят: ${reason}`,
  rollbackWithDomain: '--rollback не принимает --domain: откат берёт домен из манифеста',
  noFixes: 'чинить нечего: охваченные проверки в порядке',
  nothingSelected: 'не выбрано ни одной охваченной проверки',
  auditFailed: (detail: string): string => `аудит сайта не удался: ${detail}`,
  serverNginx: 'nginx',
  serverCaddy: 'Caddy',
  serverUnknown: 'автоматически не чиним: nginx или Caddy не найден',
  serverNoDomain: (domain: string): string =>
    `ни nginx, ни Caddy не содержат блок для ${domain}: показываю рецепты`,
  serverAmbiguous: (domain: string): string =>
    `домен ${domain} есть и в nginx, и в Caddy: не угадываю, показываю рецепты`,
  planTitle: (domain: string, server: string): string =>
    `План починки ${domain} (${server})`,
  planEdit: (path: string): string => `  правка: ${path}`,
  planSkip: (target: string, detail: string): string => `  пропуск: ${target} — ${detail}`,
  planChecks: (checks: string): string => `Проверки к починке: ${checks}`,
  diffTitle: (path: string): string => `Дифф ${path}`,
  emptyDiff: 'изменений нет',
  confirm: 'Применить? [y/N] ',
  noTTY: 'нет терминала для подтверждения: повторите с --yes',
  declined: 'Отменено, ничего не меняем',
  dryRun: '--dry-run: показал план и вышел, ничего не меняю',
  backupAt: (dir: string): string => `Бэкап: ${dir}`,
  applied: 'Изменения применены, конфиг проверен, служба перезагружена',
  validateFailed: (detail: string): string =>
    `Конфиг не прошёл проверку, вернул файлы из бэкапа: ${detail}`,
  reloadFailed: (detail: string): string =>
    `Служба не перезагрузилась, вернул файлы из бэкапа: ${detail}`,
  recheckWait: 'Жду 5 секунд и проверяю сайт снаружи заново',
  recheckFixed: (id: string): string => `  исправлено: ${id}`,
  recheckStill: (id: string): string => `  ещё нет: ${id}`,
  cdnHint: 'Возможно, перед сервером кэш или CDN: обновите кэш и проверьте снова',
  rollbackHint: (command: string): string => `Откат: ${command}`,
  backupMissing: (path: string): string => `в бэкапе нет файла ${path}`,
  manifestMissing: (dir: string): string => `в ${dir} нет manifest.json`,
  rollbackDone: 'Откат выполнен, конфиг проверен, служба перезагружена',
  rollbackValidateFailed: (detail: string): string =>
    `После отката конфиг не прошёл проверку: ${detail}`,
  rollbackCommand: (dir: string): string =>
    `sudo npx @borodatych/security fix --rollback ${dir}`,
  recipeTitle: (id: string, stack: string): string => `Рецепт ${id} (${stack})`,
  recipeNoAuto: (id: string): string => `${id}: автоматически не чиним, показываю рецепт`,
  recipeStep: (step: string): string => `  - ${step}`,
  recipeConfig: (lang: string): string => `  Конфиг (${lang}):`,
  recipeVerify: (code: string): string => `  Проверка: ${code}`,
  recipeRisk: (risk: string): string => `  Риск: ${risk}`,
  recipeStackCaddy: 'Caddy',
  recipeStackGeneric: 'общий',
  rollbackTitle: (dir: string): string => `Откат по бэкапу ${dir}`,
  jsonApplied: (count: number): string => `файлов изменено: ${count}`,
  helpText: [
    'borodatych-security fix — единственная команда, которая меняет сервер',
    '',
    'использование: sudo borodatych-security fix --domain example.ru [параметры]',
    '',
    '  --domain <host>     домен, который чиним',
    '  --only id,id        только эти проверки',
    '  --yes               не спрашивать подтверждение',
    '  --dry-run           показать дифф и выйти',
    '  --json              машинный итог',
    '  --rollback <путь>   вернуть файлы из каталога бэкапа',
    '',
    'охват: nginx и Caddy; web.headers, web.banner, web.sourcemaps, web.ratelimit (только nginx)',
  ],
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
  account,
  fix,
}

export type Ru = typeof ru
