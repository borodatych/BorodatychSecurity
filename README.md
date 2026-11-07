# Borodatych Security

Проверка защиты сервера и сайта: что открыто наружу и чем это закрыть.
Русский отчёт «что сломано → чем чинить», 27 проверок в 6 разделах, CLI и MCP для агентов.

**Проверки только читают.** Они ничего не меняют на сервере, не ставят пакеты и не перезапускают
службы. Меняет сервер ровно одна команда — [`fix`](#починка-fix): только после показа диффа и
подтверждения, с бэкапом, проверкой конфига, откатом при сбое и командой отката.
Секреты (значения из `.env`, ключи, пароли) в отчёт не попадают.

## Быстрый старт

```bash
# проверка сервера изнутри, нужен root
sudo npx @borodatych/security

# проверка сайта снаружи с любой машины
npx @borodatych/security --domain example.ru
```

Подключение MCP для агентов — [docs/manuals/mcpSetup.md](docs/manuals/mcpSetup.md).

## Что проверяет

| Раздел | О чём |
|---|---|
| 1. База | поддержка ОС, автообновления, висящие обновления, Ubuntu Pro, SSH по ключам |
| 2. Что торчит наружу | слушающие порты, обход UFW через Docker, сетевой экран, админка NPM |
| 3. Изоляция | root и privileged в контейнерах, docker.sock, тома, песочница systemd, EOL-рантаймы |
| 4. Защита от перебора и ботов | Fail2ban, баны для контейнеров, CrowdSec |
| 5. Сайт снаружи | утечки, source maps, заголовки, TLS, CORS, cookie, лимиты, версии ПО |
| 6. Хозяйство | бэкап вне сервера, внешний мониторинг |

К каждой проверке — рецепт починки: шаги, рабочий конфиг под ваш стек (nginx, Caddy, Apache, NPM, Traefik, Cloudflare, Express, Next.js) и стартовый CSP по ресурсам сайта.

Подробности по каждой проверке — [docs/checks.md](docs/checks.md).
Возможности продукта — [docs/functional.md](docs/functional.md), план — [docs/roadmap.md](docs/roadmap.md).

## Установка и запуск

Одной строкой, без установки:

```bash
npx @borodatych/security
```

Полная проверка требует root: без прав часть проверок честно скажет «не проверить».

```bash
sudo npx @borodatych/security
# или из-под root
npx @borodatych/security
```

Можно поставить глобально:

```bash
npm install -g @borodatych/security
borodatych-security
```

Из исходников:

```bash
bun install
bun run build
node dist/cli.js
```

## Флаги

| Флаг | Что делает |
|---|---|
| `--json` | отчёт в JSON (стабильная схема, удобно агенту) |
| `--only id,id` | выполнить только эти проверки |
| `--skip id,id` | пропустить эти проверки |
| `--domain <host>` | проверить сайт снаружи (раздел 5), только имя хоста: `example.ru` |
| `--quiet` | не печатать строку про сайт в конце текстового отчёта |
| `--help`, `-h` | справка |
| `--version`, `-v` | версия |
| `mcp` | поднять MCP-сервер по stdio для агента |
| `fix --domain <host>` | починить сайт на сервере: nginx или Caddy, только после диффа и подтверждения |
| `fix --rollback <путь>` | вернуть файлы из каталога бэкапа |
| `login` | войти через браузер и сохранить токен |
| `logout` | удалить сохранённый токен |
| `whoami [--json]` | кто вошёл и какие домены открыты |

Примеры:

```bash
sudo npx @borodatych/security --only ssh.auth,net.listen
npx @borodatych/security --domain example.ru --json
sudo npx @borodatych/security --skip web.ratelimit

# починка: сначала дифф, потом подтверждение
sudo npx @borodatych/security fix --domain example.ru --dry-run
sudo npx @borodatych/security fix --domain example.ru --yes
```

## Починка fix

`fix` — единственная команда, которая меняет сервер. Она чинит только сайт снаружи и только то,
что умеет делать безопасно. Остальное печатает рецептом из каталога и не трогает.

| Проверка | nginx | Caddy (v2, Caddyfile) |
|---|---|---|
| `web.headers` | HSTS без preload, nosniff, Referrer-Policy, `X-Frame-Options: SAMEORIGIN`, CSP только в `Content-Security-Policy-Report-Only` | те же заголовки в `header {}` |
| `web.banner` | `server_tokens off;` | `header -Server` |
| `web.sourcemaps` | `location ~* \.map$ { return 404; }` | `@maps path *.map` + `respond 404` |
| `web.ratelimit` | `limit_req_zone` в `conf.d` и `limit_req` в server | только рецепт |

Порядок работы:

1. проверяет, что запущено на Linux и от root;
2. проверяет доступ к домену;
3. проверяет сайт снаружи (по умолчанию без `ratelimit`: эта проверка шлёт 30 быстрых запросов);
4. находит nginx (`nginx -T`) или Caddy (`/etc/caddy/Caddyfile`) и блок с нужным доменом;
5. показывает единый дифф и список «что будет сделано / что пропущено»;
6. спрашивает `Применить? [y/N]` (без TTY нужен `--yes`);
7. кладёт бэкап в `/var/backups/borodatych-security/<ISO-время>/`, пишет атомарно, сохраняет права;
8. проверяет конфиг (`nginx -t` / `caddy validate`) и перезагружает службу;
9. при сбое проверки или перезагрузки возвращает **все** файлы из бэкапа и удаляет созданные;
10. через 5 секунд перепроверяет сайт снаружи и печатает команду отката.

Если перепроверка не прошла, `fix` не откатывает правки: скорее всего, перед сервером кэш или CDN.
Подробно — [docs/manuals/fix.md](docs/manuals/fix.md).

```bash
# посмотреть план и дифф, ничего не меняя
sudo npx @borodatych/security fix --domain example.ru --dry-run

# применить только заголовки
sudo npx @borodatych/security fix --domain example.ru --only web.headers

# откатить по пути из вывода fix
sudo npx @borodatych/security fix --rollback /var/backups/borodatych-security/2026-11-07T12:00:00.000Z
```

`fix` не трогает блок, если в нём уже есть такая же директива (`add_header`, `server_tokens`):
скажет «уже задано вручную, не трогаю». Если конфиг не удалось разобрать однозначно, файл
остаётся как был, а в отчёт попадает рецепт.

## Коды выхода

| Код | Значение |
|---|---|
| 0 | дыр нет (могут быть `warn`, `skip`, `unknown`) |
| 1 | есть хотя бы одна дыра (`fail`); у `fix` — сбой применения или перепроверка не прошла |
| 2 | ошибка CLI: неизвестный флаг или id проверки; у `fix` — нет root, домена или доступа |

## Сайт и кабинет

Сайт [security.borodatych.ru](https://security.borodatych.ru) проверяет домен снаружи — без установки.
Пакет проверяет сервер изнутри. В кабинете на сайте — история проверок, слежение за сайтом
и загрузка отчёта пакета (`npx @borodatych/security --json > report.json`).

## Вход и платные функции

Проверки сервера и сайта, `list_checks`, `explain_check` и `get_recipe` бесплатны и работают без входа.
Починка по плану (`fix_plan`, `verify_fix` в MCP) бесплатна для трёх доменов; дальше нужен пропуск
в кабинете на сайте.

```bash
npx @borodatych/security login    # код и ссылка, вход в браузере, токен сохраняется
npx @borodatych/security whoami   # кто вошёл и сколько бесплатных доменов осталось
npx @borodatych/security logout   # забыть токен
```

Токен лежит в `~/.config/borodatych-security/token` с правами `600`, каталог — `700`.
Под `sudo` команды берут токен обычного пользователя (`SUDO_USER`), поэтому `sudo … login` не нужен.
Для MCP токен можно передать переменной `BOROSEC_TOKEN` в окружении клиента.

## MCP: проверки для агента

CLI и MCP — один движок. MCP тоже только читает и ничего не меняет на сервере.

Claude Code:

```bash
claude mcp add borodatych-security -- npx -y @borodatych/security mcp
```

Любой клиент с JSON-конфигом (`mcpServers`):

```json
{
  "mcpServers": {
    "borodatych-security": {
      "command": "npx",
      "args": ["-y", "@borodatych/security", "mcp"]
    }
  }
}
```

Инструменты:

| Инструмент | Что делает |
|---|---|
| `audit_server` | проверяет сервер (всё, кроме сайта), отдаёт JSON-отчёт как `--json` |
| `audit_site` | проверяет сайт снаружи по домену; `ratelimit` выключен по умолчанию |
| `explain_check` | объясняет проверку: что проверяет, что считается проблемой, чем чинить |
| `list_checks` | список проверок: id, раздел, важность, название |
| `fix_plan` | план починки по домену: только `fail` и `warn`, с рецептами под найденный стек (нужен доступ) |
| `get_recipe` | рецепт по id проверки: шаги, конфиг, проверка и риски (бесплатно) |
| `verify_fix` | одна проверка сайта после правки, `fixed=true` только при `ok` (нужен доступ) |

Агент читает отчёт и предлагает правки, но применяет их только после согласия пользователя.
Пошаговая настройка для Claude Code, VibeIDE и Cursor — [docs/manuals/mcpSetup.md](docs/manuals/mcpSetup.md).

## Документы

- [docs/idea.md](docs/idea.md) — замысел продукта
- [docs/checks.md](docs/checks.md) — каталог проверок
- [docs/functional.md](docs/functional.md) — что умеет продукт
- [docs/roadmap.md](docs/roadmap.md) — план и сделанное
- [docs/manuals/mcpSetup.md](docs/manuals/mcpSetup.md) — подключение MCP
- [docs/manuals/fix.md](docs/manuals/fix.md) — починка сайта и откат

## Лицензия

AGPL-3.0: пользоваться, менять и запускать у себя бесплатно
Кто встраивает пакет в свой сетевой сервис, открывает и свои правки — или договаривается с автором о коммерческой лицензии
