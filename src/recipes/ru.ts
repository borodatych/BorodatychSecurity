import type { Recipe } from './types'

/**
 * Рецепты починки по-русски: для всех проверок registry
 * Шаг — одно предложение, без точки в конце
 */
export const recipes: Record<string, Recipe> = {
  'base.os': {
    checkId: 'base.os',
    stacks: {},
    generic: {
      steps: [
        'Узнайте текущий выпуск через lsb_release -a',
        'Сделайте бэкап и обновите все пакеты до последних версий',
        'Запустите do-release-upgrade и дойдите до поддерживаемого LTS',
        'Проверьте, что новые репозитории в sources.list рабочие',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo apt update
sudo apt full-upgrade -y
sudo apt install -y update-manager-core
sudo do-release-upgrade`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'grep PRETTY_NAME /etc/os-release',
    },
    risks: ['обновление выпуска требует простоя и перезагрузки', 'перед обновлением сделайте бэкап'],
  },
  'base.autoupdates': {
    checkId: 'base.autoupdates',
    stacks: {},
    generic: {
      steps: [
        'Поставьте пакет unattended-upgrades',
        'Включите ежедневную загрузку списков и установку обновлений',
        'Оставьте только обновления безопасности, если не хотите неожиданных мажорных версий',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo apt update
sudo apt install -y unattended-upgrades
sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
sudo systemctl enable --now unattended-upgrades`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'systemctl is-enabled unattended-upgrades && systemctl is-active unattended-upgrades',
    },
    risks: ['автообновления могут перезапустить службы ночью'],
  },
  'base.pending': {
    checkId: 'base.pending',
    stacks: {},
    generic: {
      steps: [
        'Установите висящие обновления безопасности',
        'Перезагрузите сервер, если появился файл reboot-required',
        'Проверьте, что после перезагрузки все службы поднялись',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo apt update
sudo apt upgrade -y
if [ -f /var/run/reboot-required ]; then sudo reboot; fi`,
      },
    },
    verify: {
      lang: 'bash',
      code: "test -f /var/run/reboot-required || echo 'перезагрузка не требуется'",
    },
    risks: ['перезагрузка прерывает работу сервисов', 'перед перезагрузкой проверьте автозапуск'],
  },
  'base.livepatch': {
    checkId: 'base.livepatch',
    stacks: {},
    generic: {
      steps: [
        'Подключите Ubuntu Pro, для физлиц он бесплатен до 5 машин',
        'Включите Livepatch, чтобы ядро обновлялось без перезагрузки',
        'Проверьте, что токен сохранён и служба активна',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo pro attach
sudo pro enable livepatch`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'sudo pro status',
    },
    risks: ['Livepatch не покрывает все обновления ядра — перезагрузки иногда всё равно нужны'],
  },
  'ssh.auth': {
    checkId: 'ssh.auth',
    stacks: {},
    generic: {
      steps: [
        'Убедитесь, что вход по ключу работает во втором терминале',
        'Выключите пароли и keyboard-interactive',
        'Разрешите root только по ключу или запретите совсем',
        'Проверьте конфиг через sshd -t и перезагрузите службу',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
EOF
sudo sshd -t && sudo systemctl reload ssh`,
      },
    },
    verify: {
      lang: 'bash',
      code: "sudo sshd -T | grep -E '^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication)'",
    },
    risks: ['без рабочего ключа можно потерять доступ — проверьте вход вторым терминалом'],
  },
  'net.listen': {
    checkId: 'net.listen',
    stacks: {},
    generic: {
      steps: [
        'Найдите процесс, который слушает лишний порт',
        'Переведите службу на 127.0.0.1, если она нужна только локально',
        'Если сервис нужен снаружи, ограничьте порт в сетевом экране',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo ss -ltnp
sudo ufw deny 6379/tcp`,
      },
    },
    verify: {
      lang: 'bash',
      code: "sudo ss -ltnup | grep -E '0\\.0\\.0\\.0|\\[::\\]'",
    },
    risks: ['закрытие порта может прервать внешний доступ к сервису'],
  },
  'net.docker-bypass': {
    checkId: 'net.docker-bypass',
    stacks: {},
    generic: {
      steps: [
        'Публикуйте порт только на 127.0.0.1 в compose или docker run',
        'Добавьте правило в цепочку DOCKER-USER для доступа с нужных адресов',
        'Не полагайтесь на UFW: порты Docker идут мимо цепочки INPUT',
      ],
      snippet: {
        lang: 'yaml',
        code: `services:
  db:
    ports:
      - "127.0.0.1:5432:5432"`,
      },
    },
    verify: {
      lang: 'bash',
      code: "docker ps --format '{{.Names}}\\t{{.Ports}}' | grep '0.0.0.0'",
    },
    risks: ['правила DOCKER-USER сбрасываются при перезапуске Docker без сохранения'],
  },
  'net.firewall': {
    checkId: 'net.firewall',
    stacks: {},
    generic: {
      steps: [
        'Разрешите SSH до включения экрана, иначе потеряете доступ',
        'Включите запрет входящих по умолчанию',
        'Разрешите только нужные порты: SSH, HTTP и HTTPS',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80,443/tcp
sudo ufw enable`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'sudo ufw status verbose',
    },
    risks: ['перед enable разрешите SSH-порт, иначе потеряете доступ'],
  },
  'net.npm-admin': {
    checkId: 'net.npm-admin',
    stacks: {},
    generic: {
      steps: [
        'Опубликуйте порт 81 только на 127.0.0.1',
        'Перезапустите контейнер Nginx Proxy Manager',
        'Ходите в админку через SSH-туннель, а не напрямую из интернета',
      ],
      snippet: {
        lang: 'yaml',
        code: `services:
  npm:
    ports:
      - "127.0.0.1:81:81"
      - "80:80"
      - "443:443"`,
      },
    },
    verify: {
      lang: 'bash',
      code: "docker ps --format '{{.Names}}\\t{{.Ports}}' | grep ':81->'",
    },
    risks: ['админка станет доступна только через SSH-туннель'],
  },
  'docker.root': {
    checkId: 'docker.root',
    stacks: {},
    generic: {
      steps: [
        'Запустите контейнер от непривилегированного пользователя',
        'Сбросьте все capabilities и добавьте только нужные',
        'Включите no-new-privileges, чтобы процесс не мог поднять права',
      ],
      snippet: {
        lang: 'yaml',
        code: `services:
  app:
    user: "1000:1000"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true`,
      },
    },
    verify: {
      lang: 'bash',
      code: "docker inspect <container> --format '{{.Config.User}} {{.HostConfig.SecurityOpt}}'",
    },
    risks: ['контейнеру может понадобиться доступ к своим каталогам или порту'],
  },
  'docker.sock': {
    checkId: 'docker.sock',
    stacks: {},
    generic: {
      steps: [
        'Уберите монтирование /var/run/docker.sock из контейнера',
        'Если доступ к Docker API нужен, поставьте прокси только на чтение',
        'Ограничьте через прокси только необходимые методы API',
      ],
      snippet: {
        lang: 'yaml',
        code: `services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1
      IMAGES: 1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    read_only: true`,
      },
    },
    verify: {
      lang: 'bash',
      code: "docker inspect <container> --format '{{range .Mounts}}{{.Source}}{{\"\\n\"}}{{end}}'",
    },
    risks: ['прокси тоже получает доступ к Docker API — ограничьте разрешения'],
  },
  'docker.mounts': {
    checkId: 'docker.mounts',
    stacks: {},
    generic: {
      steps: [
        'Замените широкие тома на конкретные каталоги приложения',
        'Монтируйте данные только на чтение, если запись не нужна',
        'Уберите монтирование корня, /etc и домашних каталогов',
      ],
      snippet: {
        lang: 'yaml',
        code: `services:
  app:
    volumes:
      - /srv/app/data:/data:ro`,
      },
    },
    verify: {
      lang: 'bash',
      code: "docker inspect <container> --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{\"\\n\"}}{{end}}'",
    },
    risks: ['после сужения тома приложение может потерять доступ к файлам'],
  },
  'systemd.sandbox': {
    checkId: 'systemd.sandbox',
    stacks: {},
    generic: {
      steps: [
        'Создайте drop-in для службы через systemctl edit',
        'Добавьте ограничения файловой системы, capabilities и системных вызовов',
        'Перезагрузите службу и проверьте журнал на ошибки',
        'Для Node и Bun не включайте MemoryDenyWriteExecute: JIT не заработает',
      ],
      snippet: {
        lang: 'ini',
        code: `[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=false`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'systemd-analyze security <unit> --no-pager',
    },
    risks: ['жёсткие ограничения могут сломать службу — проверяйте журнал после перезапуска'],
  },
  'runtime.eol': {
    checkId: 'runtime.eol',
    stacks: {},
    generic: {
      steps: [
        'Определите, какие рантаймы и версии установлены',
        'Обновите их до поддерживаемых версий',
        'Обновите образы контейнеров и пересоберите зависимости',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo apt update
sudo apt install -y nodejs
node --version`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'node --version; bun --version; php -v; python3 --version; psql --version',
    },
    risks: ['обновление рантайма может потребовать пересборки зависимостей'],
  },
  'f2b.active': {
    checkId: 'f2b.active',
    stacks: {},
    generic: {
      steps: [
        'Поставьте fail2ban из репозитория',
        'Включите службу и джейл sshd',
        'Добавьте свой IP в ignoreip, чтобы не заблокировать себя',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo apt update
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'sudo fail2ban-client status',
    },
    risks: ['неверный jail.local может заблокировать свой IP — добавьте ignoreip'],
  },
  'f2b.docker': {
    checkId: 'f2b.docker',
    stacks: {},
    generic: {
      steps: [
        'В jail.local задайте цепочку DOCKER-USER',
        'Перезапустите fail2ban',
        'Проверьте, что правила появляются в цепочке DOCKER-USER',
      ],
      snippet: {
        lang: 'ini',
        code: `[DEFAULT]
banaction = iptables-multiport
chain = DOCKER-USER`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'sudo iptables -L DOCKER-USER -n',
    },
    risks: ['правила в DOCKER-USER не сохраняются после перезагрузки без iptables-persistent'],
  },
  crowdsec: {
    checkId: 'crowdsec',
    stacks: {},
    generic: {
      steps: [
        'Поставьте CrowdSec и подключите CAPI',
        'Поставьте баунсер, например firewall-bouncer',
        'Проверьте, что баунсер видит решения CrowdSec: дата последнего pull в cscli bouncers list свежая',
        'Если pull старый — перезапустите баунсер и посмотрите его журнал',
      ],
      snippet: {
        lang: 'bash',
        code: `curl -s https://install.crowdsec.net | sudo sh
sudo apt install -y crowdsec
sudo cscli capi register
sudo apt install -y crowdsec-firewall-bouncer-iptables`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'sudo cscli bouncers list -o json && sudo cscli capi status',
    },
    risks: ['баунсер меняет правила iptables или nftables — проверьте доступ по SSH'],
  },
  'ops.backup': {
    checkId: 'ops.backup',
    stacks: {},
    generic: {
      steps: [
        'Выберите инструмент с шифрованием и удалённым хранилищем',
        'Настройте запуск по таймеру systemd или cron',
        'Проверьте восстановление на отдельной машине',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo apt install -y restic
export RESTIC_REPOSITORY=s3:https://s3.example.ru/backup
restic init
restic backup /srv /etc`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'restic snapshots',
    },
    risks: ['без проверки восстановления бэкап может оказаться нерабочим'],
  },
  'ops.monitor': {
    checkId: 'ops.monitor',
    stacks: {},
    generic: {
      steps: [
        'Поставьте Uptime Kuma или аналог на другой машине',
        'Добавьте проверки сайта и SSH с внешней точки',
        'Настройте оповещения в Telegram или почту',
      ],
      snippet: {
        lang: 'yaml',
        code: `services:
  uptime-kuma:
    image: louislam/uptime-kuma:1
    ports:
      - "3001:3001"
    volumes:
      - ./data:/app/data
    restart: unless-stopped`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'curl -fsS http://127.0.0.1:3001 >/dev/null && echo ok',
    },
    risks: ['мониторинг на том же сервере не заметит его падение'],
  },
  'ops.canary': {
    checkId: 'ops.canary',
    stacks: {},
    generic: {
      steps: [
        'На canarytokens.org создайте токен типа AWS API Keys, в memo укажите, куда положите файл',
        'Из России сайт открывается только через прокси, а ловушки срабатывают и без него',
        'Сначала создайте тестовый web-токен, откройте его curl и убедитесь, что письмо дошло, а не в спаме',
        'Разложите ключи файлами туда, куда чужим лезть незачем, с правдоподобными именами',
        'Права 600, владелец root:root; token и auth от токенов храните вне сервера',
        'Запускайте проверку с --canary и путями приманок',
      ],
      snippet: {
        lang: 'bash',
        code: `sudo install -m 600 -o root -g root accessKeys.csv /root/accessKeys.csv
sudo install -m 600 -o root -g root rootkey.csv /opt/docker/aws-rootkey-old.csv`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'sudo borodatych-security --only ops.canary --canary /root/accessKeys.csv,/opt/docker/aws-rootkey-old.csv',
    },
    risks: [
      'срабатывает использование ключей, а не чтение файла: это датчик на вора с инструментами',
      'датчик без проверенной доставки писем — декорация',
    ],
  },

  'web.secrets': {
    checkId: 'web.secrets',
    stacks: {
      nginx: {
        steps: [
          'Добавьте location с запретом служебных путей',
          'Отдавайте 444, чтобы не раскрывать наличие файла',
          'Проверьте, что правило стоит выше отдачи статики',
        ],
        snippet: {
          lang: 'nginx',
          code: `location ~* /(\\.env|\\.git|config\\.json|\\.DS_Store|backup\\.sql|server-status|phpinfo\\.php) {
    return 444;
}`,
        },
      },
      caddy: {
        steps: [
          'Опишите matcher для служебных путей',
          'Отвечайте 404 до обработки основного сайта',
        ],
        snippet: {
          lang: 'caddyfile',
          code: `@secrets path /.env /.git/* /config.json /.DS_Store /backup.sql /server-status /phpinfo.php
respond @secrets 404`,
        },
      },
      apache: {
        steps: [
          'Запретите служебные пути через LocationMatch',
          'Проверьте, что mod_authz_core включён',
        ],
        snippet: {
          lang: 'apache',
          code: `<LocationMatch "(?i)/(\\.env|\\.git|config\\.json|\\.DS_Store|backup\\.sql|server-status|phpinfo\\.php)">
    Require all denied
</LocationMatch>`,
        },
      },
      npm: {
        steps: [
          'Откройте Advanced в настройках хоста Nginx Proxy Manager',
          'Вставьте запрет служебных путей в конфиг nginx',
          'Сохраните и проверьте, что сайт открывается',
        ],
        snippet: {
          lang: 'nginx',
          code: `location ~* /(\\.env|\\.git|config\\.json|\\.DS_Store|backup\\.sql|server-status|phpinfo\\.php) {
    return 444;
}`,
        },
      },
      cloudflare: {
        steps: [
          'Создайте Security Rule для служебных путей',
          'Условие — регулярное выражение по URI Path',
          'Действие — Block до попадания запроса на origin',
        ],
        snippet: {
          lang: 'text',
          code: `Security Rules → Create rule
Field: URI Path, operator: matches regex
Value: (?i)/(\\.env|\\.git|config\\.json|\\.DS_Store|backup\\.sql|server-status|phpinfo\\.php)
Action: Block`,
        },
      },
      express: {
        steps: [
          'Добавьте middleware до отдачи статики и маршрутов',
          'Возвращайте 404, чтобы не подсказывать путь',
        ],
        snippet: {
          lang: 'js',
          code: `const blocked = /^\\/(?:\\.env|\\.git(?:\\/|$)|config\\.json|\\.DS_Store|backup\\.sql|server-status|phpinfo\\.php)/i

app.use((req, res, next) => {
  if (blocked.test(req.path)) {
    res.status(404).end()
    return
  }
  next()
})`,
        },
      },
      nextjs: {
        steps: [
          'Добавьте middleware в корень проекта',
          'Возвращайте 404 на служебные пути до рендера страницы',
        ],
        snippet: {
          lang: 'js',
          code: `import { NextResponse } from 'next/server'

const blocked = /^\\/(?:\\.env|\\.git(?:\\/|$)|config\\.json|\\.DS_Store|backup\\.sql|server-status|phpinfo\\.php)/i

export function middleware(request) {
  if (blocked.test(new URL(request.url).pathname)) {
    return new NextResponse(null, { status: 404 })
  }
  return NextResponse.next()
}

export const config = { matcher: '/(.*)' }`,
        },
      },
    },
    generic: {
      steps: [
        'Закройте служебные пути на прокси до попадания в приложение',
        'Отдайте на /.env, /.git и /config.json ответ 404 или 444',
        'Убедитесь, что в корне сайта нет .env, .git и дампов баз',
      ],
      snippet: {
        lang: 'text',
        code: `Запретить на прокси: /.env /.git/config /.git/HEAD /config.json /.DS_Store /backup.sql /server-status /phpinfo.php
Вернуть 404 или закрыть соединение кодом 444`,
      },
    },
    verify: {
      lang: 'bash',
      code: "for p in .env .git/config config.json backup.sql; do code=$(curl -s -o /dev/null -w '%{http_code}' \"https://{domain}/$p\"); echo \"$code $p\"; done",
    },
    risks: ['правило не должно перекрывать легальные статические файлы'],
  },
  'web.sourcemaps': {
    checkId: 'web.sourcemaps',
    stacks: {
      nginx: {
        steps: [
          'Запретите отдачу файлов с расширением .map',
          'Проверьте, что правило стоит раньше статики',
        ],
        snippet: {
          lang: 'nginx',
          code: `location ~* \\.map$ {
    return 404;
}`,
        },
      },
      caddy: {
        steps: [
          'Опишите matcher по расширению .map',
          'Отвечайте 404 до отдачи файлов',
        ],
        snippet: {
          lang: 'caddyfile',
          code: `@borodatych_security_maps path *.map
respond @borodatych_security_maps 404`,
        },
      },
      apache: {
        steps: [
          'Запретите доступ к файлам .map через FilesMatch',
          'Проверьте, что mod_authz_core включён',
        ],
        snippet: {
          lang: 'apache',
          code: `<FilesMatch "\\.map$">
    Require all denied
</FilesMatch>`,
        },
      },
      npm: {
        steps: [
          'Откройте Advanced в настройках хоста Nginx Proxy Manager',
          'Добавьте запрет файлов .map в конфиг nginx',
        ],
        snippet: {
          lang: 'nginx',
          code: `location ~* \\.map$ {
    return 404;
}`,
        },
      },
      cloudflare: {
        steps: [
          'Создайте Security Rule для URI с расширением .map',
          'Действие — Block до origin',
        ],
        snippet: {
          lang: 'text',
          code: `Security Rules → Create rule
Field: URI Path, operator: matches regex
Value: (?i)\\.map$
Action: Block`,
        },
      },
      express: {
        steps: [
          'Не отдавайте карты из express.static',
          'Добавьте маршрут-заглушку до статики',
        ],
        snippet: {
          lang: 'js',
          code: `app.get(/\\.map$/, (req, res) => {
  res.status(404).end()
})`,
        },
      },
      nextjs: {
        steps: [
          'Выключите карты исходников в production-сборке',
          'Не копируйте файлы .map на сервер',
        ],
        snippet: {
          lang: 'js',
          code: `/** @type {import('next').NextConfig} */
module.exports = {
  productionBrowserSourceMaps: false,
}`,
        },
      },
    },
    generic: {
      steps: [
        'Соберите production-версию без карт исходников',
        'Удалите файлы .map из каталога сайта',
        'Запретите отдачу *.map на прокси или CDN',
      ],
      snippet: {
        lang: 'text',
        code: `Удалить все *.map из каталога сборки
Запретить на прокси пути с расширением .map`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'curl -sI https://{domain}/assets/app.js.map | head -n 1',
    },
    risks: ['без карт сложнее разбирать ошибки — храните их в приватном хранилище'],
  },
  'web.headers': {
    checkId: 'web.headers',
    stacks: {
      nginx: {
        steps: [
          'Добавьте заголовки в server или location',
          'CSP включите в режиме Report-Only и смотрите отчёты неделю',
          'После недели без нарушений переименуйте заголовок в Content-Security-Policy',
        ],
        snippet: {
          lang: 'nginx',
          code: `server {
    listen 443 ssl;
    server_name {domain};

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Content-Security-Policy-Report-Only "{csp}" always;
}`,
        },
      },
      caddy: {
        steps: [
          'Добавьте блок header в описание сайта',
          'CSP включите в режиме Report-Only и смотрите отчёты неделю',
          'После недели без нарушений переименуйте заголовок в Content-Security-Policy',
        ],
        snippet: {
          lang: 'caddyfile',
          code: `{domain} {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        X-Frame-Options "SAMEORIGIN"
        Content-Security-Policy-Report-Only "{csp}"
    }
}`,
        },
      },
      apache: {
        steps: [
          'Добавьте заголовки в VirtualHost и включите mod_headers',
          'CSP включите в режиме Report-Only и смотрите отчёты неделю',
          'После недели без нарушений переименуйте заголовок в Content-Security-Policy',
        ],
        snippet: {
          lang: 'apache',
          code: `<VirtualHost *:443>
    ServerName {domain}
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Content-Security-Policy-Report-Only "{csp}"
</VirtualHost>`,
        },
      },
      npm: {
        steps: [
          'Откройте Advanced в настройках хоста Nginx Proxy Manager',
          'Вставьте заголовки в конфиг nginx хоста',
          'CSP сначала держите в режиме Report-Only',
        ],
        snippet: {
          lang: 'nginx',
          code: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Content-Security-Policy-Report-Only "{csp}" always;`,
        },
      },
      traefik: {
        steps: [
          'Опишите middleware headers и подключите его к роутеру',
          'CSP сначала держите в режиме Report-Only',
          'После недели без нарушений переименуйте заголовок в Content-Security-Policy',
        ],
        snippet: {
          lang: 'yaml',
          code: `services:
  app:
    labels:
      - "traefik.http.middlewares.sec.headers.stsSeconds=31536000"
      - "traefik.http.middlewares.sec.headers.stsIncludeSubdomains=true"
      - "traefik.http.middlewares.sec.headers.contentTypeNosniff=true"
      - "traefik.http.middlewares.sec.headers.referrerPolicy=strict-origin-when-cross-origin"
      - "traefik.http.middlewares.sec.headers.frameDeny=true"
      - "traefik.http.middlewares.sec.headers.customResponseHeaders.Content-Security-Policy-Report-Only={csp}"
      - "traefik.http.routers.app.middlewares=sec"`,
        },
      },
      cloudflare: {
        steps: [
          'Создайте Transform Rule на изменение заголовков ответа',
          'Добавьте HSTS, nosniff, Referrer-Policy и X-Frame-Options',
          'CSP сначала добавьте как Content-Security-Policy-Report-Only',
        ],
        snippet: {
          lang: 'text',
          code: `Transform Rules → Modify response headers
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Content-Security-Policy-Report-Only: {csp}`,
        },
      },
      express: {
        steps: [
          'Подключите helmet с HSTS без preload',
          'CSP выставляйте вручную в режиме Report-Only',
          'После недели без нарушений переименуйте заголовок в Content-Security-Policy',
        ],
        snippet: {
          lang: 'js',
          code: `import helmet from 'helmet'

app.use(
  helmet({
    contentSecurityPolicy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: false },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }),
)

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy-Report-Only', "{csp}")
  next()
})`,
        },
      },
      nextjs: {
        steps: [
          'Добавьте заголовки через headers() в next.config.js',
          'CSP сначала держите в режиме Report-Only',
          'После недели без нарушений переименуйте заголовок в Content-Security-Policy',
        ],
        snippet: {
          lang: 'js',
          code: `/** @type {import('next').NextConfig} */
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'Content-Security-Policy-Report-Only', value: "{csp}" },
]

module.exports = {
  poweredByHeader: false,
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }]
  },
}`,
        },
      },
    },
    generic: {
      steps: [
        'Выставьте HSTS, nosniff, Referrer-Policy и защиту от встраивания',
        'CSP сначала включите в режиме Report-Only и смотрите отчёты неделю',
        'После недели без нарушений переименуйте заголовок в Content-Security-Policy',
      ],
      snippet: {
        lang: 'text',
        code: `Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Content-Security-Policy-Report-Only: {csp}`,
      },
    },
    verify: {
      lang: 'bash',
      code: "curl -sI https://{domain} | grep -Ei 'strict-transport-security|content-security-policy|x-content-type-options|referrer-policy'",
    },
    risks: [
      'HSTS preload почти необратим — включайте только когда уверены в HTTPS на всех поддоменах',
      'жёсткая CSP может сломать сайт — начните с Report-Only',
    ],
  },
  'web.tls': {
    checkId: 'web.tls',
    stacks: {
      nginx: {
        steps: [
          'Продлите сертификат через certbot или acme.sh',
          'Оставьте только TLS 1.2 и TLS 1.3',
          'Проверьте автопродление и перезагрузку nginx',
        ],
        snippet: {
          lang: 'nginx',
          code: `ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;`,
        },
      },
      caddy: {
        steps: [
          'Caddy продлевает сертификаты сам, проверьте DNS и порт 80',
          'Ограничьте минимальную версию TLS',
        ],
        snippet: {
          lang: 'caddyfile',
          code: `{domain} {
    tls {
        protocols tls1.2 tls1.3
    }
}`,
        },
      },
      apache: {
        steps: [
          'Продлите сертификат и перезагрузите apache',
          'Выключите SSLv3, TLS 1.0 и TLS 1.1',
        ],
        snippet: {
          lang: 'apache',
          code: 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1',
        },
      },
      npm: {
        steps: [
          'Проверьте автопродление сертификата в Nginx Proxy Manager',
          'Добавьте ограничение протоколов в Advanced',
        ],
        snippet: {
          lang: 'nginx',
          code: 'ssl_protocols TLSv1.2 TLSv1.3;',
        },
      },
      traefik: {
        steps: [
          'Задайте минимальную версию TLS в опциях',
          'Подключите опции к роутеру',
        ],
        snippet: {
          lang: 'yaml',
          code: `tls:
  options:
    modern:
      minVersion: VersionTLS12
      maxVersion: VersionTLS13`,
        },
      },
      cloudflare: {
        steps: [
          'В SSL/TLS задайте минимальную версию TLS 1.2',
          'Включите Always Use HTTPS',
          'Проверьте, что сертификат origin не истекает',
        ],
        snippet: {
          lang: 'text',
          code: `SSL/TLS → Edge Certificates
Minimum TLS Version: TLS 1.2
Always Use HTTPS: On`,
        },
      },
    },
    generic: {
      steps: [
        'Продлите сертификат через Let\u2019s Encrypt',
        'Выключите TLS 1.0 и 1.1, оставьте TLS 1.2 и 1.3',
        'Настройте автопродление и проверку срока',
      ],
      snippet: {
        lang: 'text',
        code: `Оставить TLS 1.2 и TLS 1.3
Выключить TLS 1.0 и TLS 1.1`,
      },
    },
    verify: {
      lang: 'bash',
      code: "echo | openssl s_client -connect {domain}:443 2>/dev/null | openssl x509 -noout -dates",
    },
    risks: ['старые клиенты и оборудование могут перестать подключаться'],
  },
  'web.cors': {
    checkId: 'web.cors',
    stacks: {
      nginx: {
        steps: [
          'Разрешайте только свои origin по списку',
          'Не отражайте заголовок Origin вслепую',
          'Для credentials не используйте звёздочку',
        ],
        snippet: {
          lang: 'nginx',
          code: `map $http_origin $cors_origin {
    default "";
    "https://app.{domain}" $http_origin;
}

add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;`,
        },
      },
      caddy: {
        steps: [
          'Сопоставьте только разрешённый Origin',
          'Выставьте заголовки для этого matcher',
        ],
        snippet: {
          lang: 'caddyfile',
          code: `@cors header Origin https://app.{domain}
header @cors Access-Control-Allow-Origin "https://app.{domain}"
header @cors Access-Control-Allow-Credentials "true"`,
        },
      },
      apache: {
        steps: [
          'Сверяйте Origin с белым списком через SetEnvIf',
          'Выставляйте заголовки только для разрешённого origin',
        ],
        snippet: {
          lang: 'apache',
          code: `SetEnvIf Origin "^https://app\\.{domain}$" CORS_ORIGIN=$0
Header always set Access-Control-Allow-Origin "%{CORS_ORIGIN}e" env=CORS_ORIGIN
Header always set Access-Control-Allow-Credentials "true" env=CORS_ORIGIN`,
        },
      },
      npm: {
        steps: [
          'Откройте Advanced в настройках хоста Nginx Proxy Manager',
          'Разрешите только свои origin через map',
        ],
        snippet: {
          lang: 'nginx',
          code: `map $http_origin $cors_origin {
    default "";
    "https://app.{domain}" $http_origin;
}

add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;`,
        },
      },
      traefik: {
        steps: [
          'Опишите middleware с белым списком origin',
          'Подключите middleware к роутеру',
        ],
        snippet: {
          lang: 'yaml',
          code: `labels:
  - "traefik.http.middlewares.cors.headers.accessControlAllowOriginList=https://app.{domain}"
  - "traefik.http.middlewares.cors.headers.accessControlAllowCredentials=true"
  - "traefik.http.routers.app.middlewares=cors"`,
        },
      },
      cloudflare: {
        steps: [
          'Не открывайте CORS правилами CDN без нужды',
          'Если нужно, добавьте Transform Rule с точным origin',
          'Для credentials звёздочка запрещена',
        ],
        snippet: {
          lang: 'text',
          code: `Transform Rules → Modify response headers
Set Access-Control-Allow-Origin: https://app.{domain}
Condition: http.request.headers["origin"][0] eq "https://app.{domain}"`,
        },
      },
      express: {
        steps: [
          'Подключите пакет cors с точным origin',
          'Разрешите credentials только для своих источников',
        ],
        snippet: {
          lang: 'js',
          code: `import cors from 'cors'

app.use(cors({
  origin: 'https://app.{domain}',
  credentials: true,
}))`,
        },
      },
      nextjs: {
        steps: [
          'Выставляйте CORS только для API-маршрутов',
          'Разрешайте точный origin, а не звёздочку',
        ],
        snippet: {
          lang: 'js',
          code: `const corsHeaders = [
  { key: 'Access-Control-Allow-Origin', value: 'https://app.{domain}' },
  { key: 'Access-Control-Allow-Credentials', value: 'true' },
]

module.exports = {
  async headers() {
    return [{ source: '/api/(.*)', headers: corsHeaders }]
  },
}`,
        },
      },
    },
    generic: {
      steps: [
        'Разрешайте только свои origin по белому списку',
        'Не отражайте заголовок Origin вслепую',
        'Для credentials не используйте Access-Control-Allow-Origin: *',
      ],
      snippet: {
        lang: 'text',
        code: `Access-Control-Allow-Origin: https://app.{domain}
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, OPTIONS`,
      },
    },
    verify: {
      lang: 'bash',
      code: "curl -sI -H 'Origin: https://evil.example' https://{domain}/ | grep -i access-control",
    },
    risks: ['слишком широкий белый список возвращает дыру'],
  },
  'web.cookies': {
    checkId: 'web.cookies',
    stacks: {
      nginx: {
        steps: [
          'Добавьте флаги к cookie на прокси',
          'Проверьте, что прокси не срезает атрибуты',
        ],
        snippet: {
          lang: 'nginx',
          code: 'proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;',
        },
      },
      npm: {
        steps: [
          'Откройте Advanced в настройках хоста Nginx Proxy Manager',
          'Добавьте флаги cookie директивой proxy_cookie_flags',
        ],
        snippet: {
          lang: 'nginx',
          code: 'proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;',
        },
      },
      apache: {
        steps: [
          'Добавьте недостающие флаги через mod_headers',
          'Проверьте, что атрибуты не дублируются',
        ],
        snippet: {
          lang: 'apache',
          code: `Header always edit Set-Cookie "^((?:(?!Secure).)*)$" "$1; Secure"
Header always edit Set-Cookie "^((?:(?!HttpOnly).)*)$" "$1; HttpOnly"
Header always edit Set-Cookie "^((?:(?!SameSite).)*)$" "$1; SameSite=Lax"`,
        },
      },
      express: {
        steps: [
          'Задайте флаги в настройках сессии',
          'SameSite=None используйте только вместе с Secure',
        ],
        snippet: {
          lang: 'js',
          code: `app.use(session({
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
  },
}))`,
        },
      },
      nextjs: {
        steps: [
          'Ставьте cookie через cookies() с флагами',
          'Не отдавайте сессионную cookie без HttpOnly',
        ],
        snippet: {
          lang: 'js',
          code: `import { cookies } from 'next/headers'

const store = await cookies()
store.set('session', value, {
  secure: true,
  httpOnly: true,
  sameSite: 'lax',
  path: '/',
})`,
        },
      },
    },
    generic: {
      steps: [
        'Ставьте Secure, HttpOnly и SameSite=Lax для сессионных cookie',
        'SameSite=None только вместе с Secure',
        'Проверьте, что прокси не срезает атрибуты',
      ],
      snippet: {
        lang: 'text',
        code: 'Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/',
      },
    },
    verify: {
      lang: 'bash',
      code: 'curl -sI https://{domain}/ | grep -i set-cookie',
    },
    risks: ['HttpOnly скрывает cookie от JS — проверьте, что фронтенд её не читает'],
  },
  'web.ratelimit': {
    checkId: 'web.ratelimit',
    stacks: {
      nginx: {
        steps: [
          'Задайте зону лимита в контексте http',
          'Включите limit_req в location',
          'Отдавайте 429 при превышении',
        ],
        snippet: {
          lang: 'nginx',
          code: `limit_req_zone $binary_remote_addr zone=page:10m rate=30r/m;

server {
    location / {
        limit_req zone=page burst=20 nodelay;
        limit_req_status 429;
    }
}`,
        },
      },
      apache: {
        steps: [
          'Включите mod_ratelimit',
          'Задайте лимит для нужного location',
        ],
        snippet: {
          lang: 'apache',
          code: `<Location "/">
    SetOutputFilter RATE_LIMIT
    SetEnv rate-limit 30
</Location>`,
        },
      },
      traefik: {
        steps: [
          'Опишите middleware ratelimit',
          'Подключите его к роутеру',
        ],
        snippet: {
          lang: 'yaml',
          code: `labels:
  - "traefik.http.middlewares.ratelimit.ratelimit.average=30"
  - "traefik.http.middlewares.ratelimit.ratelimit.period=1m"
  - "traefik.http.middlewares.ratelimit.ratelimit.burst=20"
  - "traefik.http.routers.app.middlewares=ratelimit"`,
        },
      },
      cloudflare: {
        steps: [
          'Создайте Rate limiting rule на главную и API',
          'Считайте запросы по IP',
          'Действие — Block с кодом 429',
        ],
        snippet: {
          lang: 'text',
          code: `Security → WAF → Rate limiting rules
If URI Path equals /
Requests: 30 per 1 minute per IP
Action: Block with 429`,
        },
      },
      express: {
        steps: [
          'Подключите express-rate-limit',
          'Задайте окно и лимит для маршрутов',
        ],
        snippet: {
          lang: 'js',
          code: `import rateLimit from 'express-rate-limit'

app.use(rateLimit({
  windowMs: 60_000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
}))`,
        },
      },
      nextjs: {
        steps: [
          'Добавьте лимит в middleware',
          'Проверьте, что при превышении приходит 429',
          'Для нескольких инстансов храните счётчики в Redis',
        ],
        snippet: {
          lang: 'js',
          code: `import { NextResponse } from 'next/server'

const hits = new Map()

export function middleware(request) {
  const ip = request.headers.get('x-forwarded-for') ?? 'unknown'
  const now = Date.now()
  const entry = hits.get(ip)
  if (entry === undefined || entry.reset < now) {
    hits.set(ip, { count: 1, reset: now + 60_000 })
    return NextResponse.next()
  }
  entry.count += 1
  if (entry.count > 30) {
    return new NextResponse('Too Many Requests', {
      status: 429,
      headers: { 'retry-after': '60' },
    })
  }
  return NextResponse.next()
}

export const config = { matcher: '/(.*)' }`,
        },
      },
    },
    generic: {
      steps: [
        'Включите лимит на прокси по IP или ключу',
        'Отдавайте 429 с заголовком Retry-After',
        'Для главной и API задайте разные лимиты',
      ],
      snippet: {
        lang: 'text',
        code: `Лимит: 30 запросов в минуту на IP
Ответ при превышении: 429 Too Many Requests
Retry-After: 60`,
      },
    },
    verify: {
      lang: 'bash',
      code: "for i in $(seq 1 40); do curl -s -o /dev/null -w '%{http_code}' https://{domain}/; echo; done | sort | uniq -c",
    },
    risks: ['слишком жёсткий лимит заденет нормальных пользователей и поисковиков'],
  },
  'web.banner': {
    checkId: 'web.banner',
    stacks: {
      nginx: {
        steps: [
          'Выключите показ версии nginx',
          'Перезагрузите конфиг',
        ],
        snippet: {
          lang: 'nginx',
          code: 'server_tokens off;',
        },
      },
      caddy: {
        steps: [
          'Удалите заголовок Server',
          'Проверьте ответ после перезагрузки',
        ],
        snippet: {
          lang: 'caddyfile',
          code: 'header -Server',
        },
      },
      apache: {
        steps: [
          'Сократите заголовок Server до продукта',
          'Выключите подпись в ответах',
        ],
        snippet: {
          lang: 'apache',
          code: `ServerTokens Prod
ServerSignature Off`,
        },
      },
      npm: {
        steps: [
          'Откройте Advanced в настройках хоста Nginx Proxy Manager',
          'Выключите server_tokens',
        ],
        snippet: {
          lang: 'nginx',
          code: 'server_tokens off;',
        },
      },
      cloudflare: {
        steps: [
          'Проксируйте сайт через Cloudflare',
          'Cloudflare заменит Server на свой и скроет версию origin',
          'Проверьте, что DNS-запись в режиме Proxied',
        ],
        snippet: {
          lang: 'text',
          code: `DNS → запись A/AAAA → Proxy status: Proxied
Ответ будет содержать Server: cloudflare`,
        },
      },
      express: {
        steps: [
          'Выключите заголовок X-Powered-By',
          'Перезапустите приложение',
        ],
        snippet: {
          lang: 'js',
          code: "app.disable('x-powered-by')",
        },
      },
      nextjs: {
        steps: [
          'Выключите заголовок X-Powered-By в next.config.js',
          'Пересоберите и перезапустите приложение',
        ],
        snippet: {
          lang: 'js',
          code: `/** @type {import('next').NextConfig} */
module.exports = {
  poweredByHeader: false,
}`,
        },
      },
    },
    generic: {
      steps: [
        'Скройте версию в заголовке Server',
        'Уберите X-Powered-By',
        'Обновите ПО, даже если версия скрыта',
      ],
      snippet: {
        lang: 'text',
        code: `Server: nginx
X-Powered-By: удалить`,
      },
    },
    verify: {
      lang: 'bash',
      code: "curl -sI https://{domain}/ | grep -Ei '^(server|x-powered-by):'",
    },
    risks: ['скрытие версии не заменяет обновление'],
  },
}
