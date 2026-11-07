# Borodatych Security

Проверка защиты сервера и сайта: что открыто наружу и чем это закрыть.
Русский отчёт «что сломано → чем чинить», 27 проверок в 6 разделах, CLI и MCP для агентов.

**Инструмент только читает.** Он ничего не меняет на сервере, не ставит пакеты и не перезапускает
службы. Секреты (значения из `.env`, ключи, пароли) в отчёт не попадают.

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

Примеры:

```bash
sudo npx @borodatych/security --only ssh.auth,net.listen
npx @borodatych/security --domain example.ru --json
sudo npx @borodatych/security --skip web.ratelimit
```

## Коды выхода

| Код | Значение |
|---|---|
| 0 | дыр нет (могут быть `warn`, `skip`, `unknown`) |
| 1 | есть хотя бы одна дыра (`fail`) |
| 2 | ошибка CLI: неизвестный флаг или id проверки |

## Сайт и кабинет

Сайт [security.borodatych.ru](https://security.borodatych.ru) проверяет домен снаружи — без установки.
Пакет проверяет сервер изнутри. В кабинете на сайте — история проверок, слежение за сайтом
и загрузка отчёта пакета (`npx @borodatych/security --json > report.json`).

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

Агент читает отчёт и предлагает правки, но применяет их только после согласия пользователя.
Пошаговая настройка для Claude Code, VibeIDE и Cursor — [docs/manuals/mcpSetup.md](docs/manuals/mcpSetup.md).

## Документы

- [docs/idea.md](docs/idea.md) — замысел продукта
- [docs/checks.md](docs/checks.md) — каталог проверок
- [docs/functional.md](docs/functional.md) — что умеет продукт
- [docs/roadmap.md](docs/roadmap.md) — план и сделанное
- [docs/manuals/mcpSetup.md](docs/manuals/mcpSetup.md) — подключение MCP

## Лицензия

AGPL-3.0: пользоваться, менять и запускать у себя бесплатно
Кто встраивает пакет в свой сетевой сервис, открывает и свои правки — или договаривается с автором о коммерческой лицензии
