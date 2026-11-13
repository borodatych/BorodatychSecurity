# ПРОВЕРКИ

Каждая проверка: id, что проверяем, как (команда или файл), что считается проблемой, чем чинить
Итог проверки — один из: `ok`, `warn` (стоит поправить), `fail` (дыра), `skip` (неприменимо: нет Docker, нет NPM), `unknown` (не проверить: нет прав или команды)
Важность — `critical`, `high`, `medium`, `low`
У проверки базовая важность; находка может её поднять (у находки своя важность), итог проверки — худшая
Список и код не расходятся: тест сверяет id

## 1. База

| id | что | как | проблема | чинить | важность |
|---|---|---|---|---|---|
| base.os | ОС с живой поддержкой | `/etc/os-release` + встроенная таблица сроков поддержки Ubuntu и Debian | срок поддержки истёк или истекает за 90 дней | обновить выпуск | high |
| base.autoupdates | автообновления безопасности | Debian/Ubuntu: пакет и таймер `unattended-upgrades`, `/etc/apt/apt.conf.d/20auto-upgrades` | не стоит или выключено | поставить и включить только security | high |
| base.pending | висящие обновления безопасности и перезагрузка | `/var/run/reboot-required`, число security-обновлений (`apt-get -s upgrade`) | есть reboot-required старше 7 дней или security-обновления | перезагрузить, обновить | medium |
| base.livepatch | Ubuntu Pro / Livepatch | `pro status` | Ubuntu без Pro — warn с подсказкой, что для физлиц бесплатно до 5 машин; не Ubuntu — skip | `pro attach` | low |
| ssh.auth | SSH только по ключам | `sshd -T` (или конфиг) | `passwordauthentication yes`, `permitrootlogin yes`, `kbdinteractiveauthentication yes` | выключить пароли, root по ключу или никак | critical |

## 2. Что торчит наружу

| id | что | как | проблема | чинить | важность |
|---|---|---|---|---|---|
| net.listen | что слушает на всех адресах | `ss -ltnup` | на 0.0.0.0 или [::] слушает что-то кроме 22, 80, 443 — особенно базы (5432, 3306, 6379, 27017), админки (81, 9000, 8080), LLMNR 5355; база наружу — critical, остальное — high | слушать 127.0.0.1 или закрыть | high |
| net.docker-bypass | Docker публикует порт мимо UFW | `docker ps` с портами `0.0.0.0:` + включён ли UFW | порт опубликован на все адреса при включённом UFW — UFW его не закрывает | публиковать `127.0.0.1:порт:порт`, правило в DOCKER-USER | critical |
| net.firewall | сетевой экран | ufw/nftables/iptables | нет ни одного правила, политика ACCEPT | включить с запретом по умолчанию | medium |
| net.npm-admin | админка Nginx Proxy Manager | контейнер NPM и порт 81 | 81 опубликован на все адреса | публиковать на 127.0.0.1, ходить через SSH-туннель | high |

## 3. Изоляция

| id | что | как | проблема | чинить | важность |
|---|---|---|---|---|---|
| docker.root | контейнеры без root | `docker inspect` User, Privileged, CapAdd, SecurityOpt | Privileged, root без cap_drop, нет no-new-privileges | `user:`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]` | high |
| docker.sock | docker.sock не проброшен | `docker inspect` Mounts | `/var/run/docker.sock` в контейнере, кроме явно известных (traefik, watchtower — warn) | убрать или прокси сокета только на чтение | critical |
| docker.mounts | точечные тома | Mounts | смонтированы `/`, `/etc`, `/root`, `/home`, домашние каталоги целиком | монтировать только нужное | high |
| systemd.sandbox | песочница служб | `systemd-analyze security` для служб, которые слушают порты | оценка выше 7 | drop-in с `CapabilityBoundingSet=`, `ProtectSystem=strict`, `SystemCallFilter=@system-service` и др.; JIT (Bun, Node, Chromium) — без `MemoryDenyWriteExecute` | medium |
| runtime.eol | рантаймы без поддержки | версии `node`, `bun`, `php`, `python3`, PostgreSQL, образы в `docker ps` | версия без поддержки | обновить | medium |

## 4. Защита от перебора и ботов

| id | что | как | проблема | чинить | важность |
|---|---|---|---|---|---|
| f2b.active | Fail2ban | `fail2ban-client status` | не стоит или нет джейла sshd; без прав — не проверить | поставить, джейл sshd | high |
| f2b.docker | баны доходят до контейнеров | при Docker: `banaction` и цепочка DOCKER-USER | баны в INPUT, а порты контейнеров идут через FORWARD | `chain = DOCKER-USER` | high |
| crowdsec | CrowdSec и баунсер | `cscli` версии, `cscli bouncers list -o json` (дата последнего pull), `cscli capi status` | нет — warn; нет живого баунсера (pull старше 24 ч, ни разу, ключ отозван) или нет CAPI — fail (важность high) | поставить баунсер, подключить CAPI, перезапустить застывший баунсер | low |

## 5. Сайт снаружи

Запускается с `--domain example.ru` и с самого сервера тоже работает: это запросы по HTTPS

| id | что | как | проблема | чинить | важность |
|---|---|---|---|---|---|
| web.secrets | утечки по известным адресам | GET `/.env`, `/.git/config`, `/.git/HEAD`, `/config.json`, `/.DS_Store`, `/backup.sql`, `/server-status`, `/phpinfo.php` | ответ 200 с содержимым, похожим на настоящее (сигнатура: `[core]`, `ref:`, `KEY=`, `<title>phpinfo`) | закрыть в прокси, 404/444 | critical |
| web.sourcemaps | карты исходников | ссылки `sourceMappingURL` в JS главной и GET на них | карта отдаётся | не публиковать карты | medium |
| web.headers | заголовки безопасности | ответ главной | нет HSTS, nosniff, защиты от встраивания (X-Frame-Options или frame-ancestors), Referrer-Policy; CSP нет — warn | выставить | medium |
| web.tls | сертификат и протоколы | TLS-рукопожатие | истекает через 14 дней — fail, через 30 — warn; TLS 1.0/1.1 принимаются | продлить, выключить старые | high |
| web.cors | CORS | OPTIONS и GET с чужим Origin | `Access-Control-Allow-Origin: *` вместе с `Allow-Credentials: true`, или отражение любого Origin с credentials | белый список источников | high |
| web.cookies | флаги cookie | Set-Cookie главной | сессионная cookie без Secure, HttpOnly или SameSite | выставить флаги | medium |
| web.ratelimit | лимит запросов | 30 быстрых запросов к главной | ни одного 429 — warn (не fail: лимит мог стоять на API) | лимит на прокси | low |
| web.banner | версии ПО в ответах | `Server`, `X-Powered-By` | версия видна (`nginx/1.18.0`, `PHP/7.4`) | убрать версии | low |

## 6. Хозяйство

| id | что | как | проблема | чинить | важность |
|---|---|---|---|---|---|
| ops.backup | бэкап вне сервера | таймеры и cron с `pg_dump`, `restic`, `borg`, `rclone`; куда пишут | бэкапа не нашли — warn «проверьте руками»; пишут только на этот же диск — fail | бэкап на другой хост, проверить восстановление | high |
| ops.monitor | внешний мониторинг | не проверить изнутри — всегда `unknown` с подсказкой | — | Uptime Kuma или аналог на другой машине, оповещения в Telegram | medium |
| ops.canary | датчик проникновения | пути из `--canary`: `stat` прав и владельца, содержимое не читается; без путей — `unknown` с подсказкой | приманки нет — fail; права не 600 или владелец не root:root — warn | Canarytokens (AWS API Keys), права 600, проверить доставку писем | low |
