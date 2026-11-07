import type { Recipe } from './types'

/**
 * Fix recipes in English: one per registry check
 * A step is one sentence without a trailing period
 */
export const recipes: Record<string, Recipe> = {
  'base.os': {
    checkId: 'base.os',
    stacks: {},
    generic: {
      steps: [
        'Find the current release with lsb_release -a',
        'Back up and upgrade all packages to the latest versions',
        'Run do-release-upgrade and move to a supported LTS',
        'Check that the new repositories in sources.list work',
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
    risks: ['a release upgrade needs downtime and a reboot', 'back up before the upgrade'],
  },
  'base.autoupdates': {
    checkId: 'base.autoupdates',
    stacks: {},
    generic: {
      steps: [
        'Install the unattended-upgrades package',
        'Enable daily package list updates and upgrades',
        'Keep security updates only if you do not want surprise major versions',
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
    risks: ['automatic upgrades may restart services at night'],
  },
  'base.pending': {
    checkId: 'base.pending',
    stacks: {},
    generic: {
      steps: [
        'Install the pending security updates',
        'Reboot the server if the reboot-required file exists',
        'Check that all services came back after the reboot',
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
      code: "test -f /var/run/reboot-required || echo 'no reboot required'",
    },
    risks: ['a reboot interrupts services', 'check autostart before rebooting'],
  },
  'base.livepatch': {
    checkId: 'base.livepatch',
    stacks: {},
    generic: {
      steps: [
        'Attach Ubuntu Pro, it is free for personal use on up to 5 machines',
        'Enable Livepatch so the kernel updates without a reboot',
        'Check that the token is stored and the service is active',
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
    risks: ['Livepatch does not cover every kernel update, reboots are still needed sometimes'],
  },
  'ssh.auth': {
    checkId: 'ssh.auth',
    stacks: {},
    generic: {
      steps: [
        'Make sure key login works in a second terminal',
        'Disable passwords and keyboard-interactive login',
        'Allow root by key only or disable root login entirely',
        'Validate the config with sshd -t and reload the service',
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
    risks: ['without a working key you can lose access, test login in a second terminal'],
  },
  'net.listen': {
    checkId: 'net.listen',
    stacks: {},
    generic: {
      steps: [
        'Find the process that listens on the extra port',
        'Bind the service to 127.0.0.1 if it is only needed locally',
        'If it must be public, restrict the port in the firewall',
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
    risks: ['closing a port may cut off external access to a service'],
  },
  'net.docker-bypass': {
    checkId: 'net.docker-bypass',
    stacks: {},
    generic: {
      steps: [
        'Publish the port on 127.0.0.1 only in compose or docker run',
        'Add a rule to the DOCKER-USER chain for allowed addresses',
        'Do not rely on UFW, Docker ports bypass the INPUT chain',
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
    risks: ['DOCKER-USER rules are lost when Docker restarts unless persisted'],
  },
  'net.firewall': {
    checkId: 'net.firewall',
    stacks: {},
    generic: {
      steps: [
        'Allow SSH before enabling the firewall or you will lose access',
        'Deny incoming traffic by default',
        'Allow only the ports you need: SSH, HTTP and HTTPS',
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
    risks: ['allow the SSH port before enable or you will lose access'],
  },
  'net.npm-admin': {
    checkId: 'net.npm-admin',
    stacks: {},
    generic: {
      steps: [
        'Publish port 81 on 127.0.0.1 only',
        'Restart the Nginx Proxy Manager container',
        'Reach the admin panel through an SSH tunnel, not from the internet',
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
    risks: ['the admin panel becomes reachable through an SSH tunnel only'],
  },
  'docker.root': {
    checkId: 'docker.root',
    stacks: {},
    generic: {
      steps: [
        'Run the container as a non-root user',
        'Drop all capabilities and add only what is needed',
        'Enable no-new-privileges so the process cannot gain privileges',
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
    risks: ['the container may need access to its own directories or ports'],
  },
  'docker.sock': {
    checkId: 'docker.sock',
    stacks: {},
    generic: {
      steps: [
        'Remove the /var/run/docker.sock mount from the container',
        'If Docker API access is needed, put a read-only proxy in front',
        'Allow only the API methods the container really uses',
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
    risks: ['the proxy still has Docker API access, limit its permissions'],
  },
  'docker.mounts': {
    checkId: 'docker.mounts',
    stacks: {},
    generic: {
      steps: [
        'Replace broad mounts with specific application directories',
        'Mount data read-only when writes are not needed',
        'Remove mounts of the root, /etc and home directories',
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
    risks: ['after narrowing a mount the application may lose access to files'],
  },
  'systemd.sandbox': {
    checkId: 'systemd.sandbox',
    stacks: {},
    generic: {
      steps: [
        'Create a drop-in for the unit with systemctl edit',
        'Add filesystem, capability and system call restrictions',
        'Restart the service and check the journal for errors',
        'Do not enable MemoryDenyWriteExecute for Node and Bun, JIT will break',
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
    risks: ['strict restrictions may break the service, check the journal after restart'],
  },
  'runtime.eol': {
    checkId: 'runtime.eol',
    stacks: {},
    generic: {
      steps: [
        'Find which runtimes and versions are installed',
        'Upgrade them to supported versions',
        'Update container images and rebuild dependencies',
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
    risks: ['a runtime upgrade may require rebuilding dependencies'],
  },
  'f2b.active': {
    checkId: 'f2b.active',
    stacks: {},
    generic: {
      steps: [
        'Install fail2ban from the distribution repository',
        'Enable the service and the sshd jail',
        'Add your own IP to ignoreip so you do not lock yourself out',
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
    risks: ['a wrong jail.local can block your own IP, add ignoreip'],
  },
  'f2b.docker': {
    checkId: 'f2b.docker',
    stacks: {},
    generic: {
      steps: [
        'Set the DOCKER-USER chain in jail.local',
        'Restart fail2ban',
        'Check that rules appear in the DOCKER-USER chain',
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
    risks: ['DOCKER-USER rules are not kept across reboots without iptables-persistent'],
  },
  crowdsec: {
    checkId: 'crowdsec',
    stacks: {},
    generic: {
      steps: [
        'Install CrowdSec and register with CAPI',
        'Install a bouncer such as firewall-bouncer',
        'Check that the bouncer sees CrowdSec decisions',
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
      code: 'sudo cscli bouncers list && sudo cscli capi status',
    },
    risks: ['the bouncer changes iptables or nftables rules, check SSH access'],
  },
  'ops.backup': {
    checkId: 'ops.backup',
    stacks: {},
    generic: {
      steps: [
        'Choose a tool with encryption and remote storage',
        'Schedule it with a systemd timer or cron',
        'Test a restore on a separate machine',
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
    risks: ['without a restore test a backup may turn out to be unusable'],
  },
  'ops.monitor': {
    checkId: 'ops.monitor',
    stacks: {},
    generic: {
      steps: [
        'Install Uptime Kuma or an equivalent on another machine',
        'Add checks for the site and SSH from an external point',
        'Set up alerts to Telegram or email',
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
    risks: ['monitoring on the same server will not notice its failure'],
  },

  'web.secrets': {
    checkId: 'web.secrets',
    stacks: {
      nginx: {
        steps: [
          'Add a location that blocks service paths',
          'Return 444 so the file existence is not revealed',
          'Check that the rule comes before static file serving',
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
          'Describe a matcher for service paths',
          'Respond with 404 before the main site handler',
        ],
        snippet: {
          lang: 'caddyfile',
          code: `@secrets path /.env /.git/* /config.json /.DS_Store /backup.sql /server-status /phpinfo.php
respond @secrets 404`,
        },
      },
      apache: {
        steps: [
          'Block service paths with LocationMatch',
          'Check that mod_authz_core is enabled',
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
          'Open Advanced in the Nginx Proxy Manager host settings',
          'Paste the service path block into the nginx config',
          'Save and check that the site still opens',
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
          'Create a Security Rule for service paths',
          'Match URI Path with a regular expression',
          'Use the Block action before the request reaches origin',
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
          'Add the middleware before static files and routes',
          'Return 404 so the path is not advertised',
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
          'Add a middleware at the project root',
          'Return 404 for service paths before rendering the page',
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
        'Block service paths at the proxy before the application sees them',
        'Return 404 or 444 for /.env, /.git and /config.json',
        'Make sure the site root has no .env, .git or database dumps',
      ],
      snippet: {
        lang: 'text',
        code: `Block at the proxy: /.env /.git/config /.git/HEAD /config.json /.DS_Store /backup.sql /server-status /phpinfo.php
Return 404 or close the connection with code 444`,
      },
    },
    verify: {
      lang: 'bash',
      code: "for p in .env .git/config config.json backup.sql; do code=$(curl -s -o /dev/null -w '%{http_code}' \"https://{domain}/$p\"); echo \"$code $p\"; done",
    },
    risks: ['the rule must not shadow legitimate static files'],
  },
  'web.sourcemaps': {
    checkId: 'web.sourcemaps',
    stacks: {
      nginx: {
        steps: [
          'Block files with the .map extension',
          'Check that the rule comes before static file serving',
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
          'Describe a matcher for the .map extension',
          'Respond with 404 before serving files',
        ],
        snippet: {
          lang: 'caddyfile',
          code: `@maps path *.map
respond @maps 404`,
        },
      },
      apache: {
        steps: [
          'Block .map files with FilesMatch',
          'Check that mod_authz_core is enabled',
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
          'Open Advanced in the Nginx Proxy Manager host settings',
          'Add the .map block to the nginx config',
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
          'Create a Security Rule for URIs ending in .map',
          'Use the Block action before origin',
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
          'Do not serve maps from express.static',
          'Add a stub route before static files',
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
          'Disable source maps in the production build',
          'Do not copy .map files to the server',
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
        'Build a production version without source maps',
        'Delete .map files from the site directory',
        'Block *.map at the proxy or CDN',
      ],
      snippet: {
        lang: 'text',
        code: `Delete all *.map files from the build directory
Block paths with the .map extension at the proxy`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'curl -sI https://{domain}/assets/app.js.map | head -n 1',
    },
    risks: ['without maps debugging production is harder, keep them in private storage'],
  },
  'web.headers': {
    checkId: 'web.headers',
    stacks: {
      nginx: {
        steps: [
          'Add the headers in server or location',
          'Start CSP in Report-Only mode and watch reports for a week',
          'After a week without violations rename it to Content-Security-Policy',
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
          'Add a header block to the site definition',
          'Start CSP in Report-Only mode and watch reports for a week',
          'After a week without violations rename it to Content-Security-Policy',
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
          'Add the headers in the VirtualHost and enable mod_headers',
          'Start CSP in Report-Only mode and watch reports for a week',
          'After a week without violations rename it to Content-Security-Policy',
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
          'Open Advanced in the Nginx Proxy Manager host settings',
          'Paste the headers into the host nginx config',
          'Keep CSP in Report-Only mode at first',
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
          'Define a headers middleware and attach it to the router',
          'Keep CSP in Report-Only mode at first',
          'After a week without violations rename it to Content-Security-Policy',
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
          'Create a Transform Rule that modifies response headers',
          'Add HSTS, nosniff, Referrer-Policy and X-Frame-Options',
          'Add CSP as Content-Security-Policy-Report-Only first',
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
          'Enable helmet with HSTS but without preload',
          'Set CSP manually in Report-Only mode',
          'After a week without violations rename it to Content-Security-Policy',
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
          'Add headers through headers() in next.config.js',
          'Keep CSP in Report-Only mode at first',
          'After a week without violations rename it to Content-Security-Policy',
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
        'Set HSTS, nosniff, Referrer-Policy and anti-framing',
        'Start CSP in Report-Only mode and watch reports for a week',
        'After a week without violations rename it to Content-Security-Policy',
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
      'HSTS preload is almost irreversible, enable it only when every subdomain is HTTPS',
      'a strict CSP can break the site, start with Report-Only',
    ],
  },
  'web.tls': {
    checkId: 'web.tls',
    stacks: {
      nginx: {
        steps: [
          'Renew the certificate with certbot or acme.sh',
          'Keep TLS 1.2 and TLS 1.3 only',
          'Check auto-renewal and nginx reload',
        ],
        snippet: {
          lang: 'nginx',
          code: `ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;`,
        },
      },
      caddy: {
        steps: [
          'Caddy renews certificates itself, check DNS and port 80',
          'Set the minimum TLS version',
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
          'Renew the certificate and reload apache',
          'Disable SSLv3, TLS 1.0 and TLS 1.1',
        ],
        snippet: {
          lang: 'apache',
          code: 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1',
        },
      },
      npm: {
        steps: [
          'Check certificate auto-renewal in Nginx Proxy Manager',
          'Add the protocol restriction in Advanced',
        ],
        snippet: {
          lang: 'nginx',
          code: 'ssl_protocols TLSv1.2 TLSv1.3;',
        },
      },
      traefik: {
        steps: [
          'Set the minimum TLS version in TLS options',
          'Attach the options to the router',
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
          'Set the minimum TLS version to 1.2 in SSL/TLS',
          'Enable Always Use HTTPS',
          'Check that the origin certificate is not expiring',
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
        'Renew the certificate with Let\'s Encrypt',
        'Disable TLS 1.0 and 1.1, keep TLS 1.2 and 1.3',
        'Set up auto-renewal and expiry checks',
      ],
      snippet: {
        lang: 'text',
        code: `Keep TLS 1.2 and TLS 1.3
Disable TLS 1.0 and TLS 1.1`,
      },
    },
    verify: {
      lang: 'bash',
      code: 'echo | openssl s_client -connect {domain}:443 2>/dev/null | openssl x509 -noout -dates',
    },
    risks: ['old clients and hardware may stop connecting'],
  },
  'web.cors': {
    checkId: 'web.cors',
    stacks: {
      nginx: {
        steps: [
          'Allow only your own origins from a list',
          'Never reflect the Origin header blindly',
          'Never use a wildcard together with credentials',
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
          'Match only the allowed Origin',
          'Set the headers for this matcher',
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
          'Match Origin against the allow list with SetEnvIf',
          'Set the headers only for the allowed origin',
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
          'Open Advanced in the Nginx Proxy Manager host settings',
          'Allow only your origins with a map',
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
          'Define a middleware with an origin allow list',
          'Attach the middleware to the router',
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
          'Do not open CORS with CDN rules unless you need to',
          'If needed, add a Transform Rule with the exact origin',
          'A wildcard is not allowed together with credentials',
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
          'Enable the cors package with an exact origin',
          'Allow credentials for your own origins only',
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
          'Set CORS for API routes only',
          'Allow the exact origin, not a wildcard',
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
        'Allow only your own origins from an allow list',
        'Never reflect the Origin header blindly',
        'Never use Access-Control-Allow-Origin: * together with credentials',
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
    risks: ['an overly broad allow list brings the hole back'],
  },
  'web.cookies': {
    checkId: 'web.cookies',
    stacks: {
      nginx: {
        steps: [
          'Add the flags to cookies at the proxy',
          'Check that the proxy does not strip the attributes',
        ],
        snippet: {
          lang: 'nginx',
          code: 'proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;',
        },
      },
      npm: {
        steps: [
          'Open Advanced in the Nginx Proxy Manager host settings',
          'Add cookie flags with the proxy_cookie_flags directive',
        ],
        snippet: {
          lang: 'nginx',
          code: 'proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;',
        },
      },
      apache: {
        steps: [
          'Add the missing flags with mod_headers',
          'Check that attributes are not duplicated',
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
          'Set the flags in the session options',
          'Use SameSite=None only together with Secure',
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
          'Set cookies through cookies() with the flags',
          'Never issue a session cookie without HttpOnly',
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
        'Set Secure, HttpOnly and SameSite=Lax for session cookies',
        'SameSite=None only together with Secure',
        'Check that the proxy does not strip the attributes',
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
    risks: ['HttpOnly hides the cookie from JS, check that the frontend does not read it'],
  },
  'web.ratelimit': {
    checkId: 'web.ratelimit',
    stacks: {
      nginx: {
        steps: [
          'Define a limit zone in the http context',
          'Enable limit_req in the location',
          'Return 429 when the limit is exceeded',
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
          'Enable mod_ratelimit',
          'Set the limit for the needed location',
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
          'Define a ratelimit middleware',
          'Attach it to the router',
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
          'Create a Rate limiting rule for the home page and API',
          'Count requests per IP',
          'Block with status 429',
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
          'Enable express-rate-limit',
          'Set the window and limit for routes',
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
          'Add the limit in middleware',
          'Check that 429 comes back when the limit is exceeded',
          'For several instances keep counters in Redis',
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
        'Enable a limit at the proxy by IP or key',
        'Return 429 with a Retry-After header',
        'Use different limits for the home page and the API',
      ],
      snippet: {
        lang: 'text',
        code: `Limit: 30 requests per minute per IP
Response when exceeded: 429 Too Many Requests
Retry-After: 60`,
      },
    },
    verify: {
      lang: 'bash',
      code: "for i in $(seq 1 40); do curl -s -o /dev/null -w '%{http_code}' https://{domain}/; echo; done | sort | uniq -c",
    },
    risks: ['an overly strict limit hits real users and search engines'],
  },
  'web.banner': {
    checkId: 'web.banner',
    stacks: {
      nginx: {
        steps: [
          'Turn off the nginx version banner',
          'Reload the config',
        ],
        snippet: {
          lang: 'nginx',
          code: 'server_tokens off;',
        },
      },
      caddy: {
        steps: [
          'Remove the Server header',
          'Check the response after reload',
        ],
        snippet: {
          lang: 'caddyfile',
          code: 'header -Server',
        },
      },
      apache: {
        steps: [
          'Reduce the Server header to the product name',
          'Turn off the signature in responses',
        ],
        snippet: {
          lang: 'apache',
          code: `ServerTokens Prod
ServerSignature Off`,
        },
      },
      npm: {
        steps: [
          'Open Advanced in the Nginx Proxy Manager host settings',
          'Turn off server_tokens',
        ],
        snippet: {
          lang: 'nginx',
          code: 'server_tokens off;',
        },
      },
      cloudflare: {
        steps: [
          'Proxy the site through Cloudflare',
          'Cloudflare replaces Server with its own value and hides the origin version',
          'Check that the DNS record is Proxied',
        ],
        snippet: {
          lang: 'text',
          code: `DNS → A/AAAA record → Proxy status: Proxied
The response will contain Server: cloudflare`,
        },
      },
      express: {
        steps: [
          'Disable the X-Powered-By header',
          'Restart the application',
        ],
        snippet: {
          lang: 'js',
          code: "app.disable('x-powered-by')",
        },
      },
      nextjs: {
        steps: [
          'Disable the X-Powered-By header in next.config.js',
          'Rebuild and restart the application',
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
        'Hide the version in the Server header',
        'Remove X-Powered-By',
        'Update the software even if the version is hidden',
      ],
      snippet: {
        lang: 'text',
        code: `Server: nginx
X-Powered-By: remove`,
      },
    },
    verify: {
      lang: 'bash',
      code: "curl -sI https://{domain}/ | grep -Ei '^(server|x-powered-by):'",
    },
    risks: ['hiding the version does not replace updating'],
  },
}
