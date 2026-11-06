/** Порты, которые допустимо слушать на всех адресах */
export const ALLOWED_PUBLIC_PORTS: ReadonlySet<number> = new Set([22, 80, 443])

/** Базы данных: открыты наружу — critical */
export const DATABASE_PORTS: ReadonlyMap<number, string> = new Map([
  [1433, 'mssql'],
  [3306, 'mysql/mariadb'],
  [5432, 'postgresql'],
  [6379, 'redis'],
  [9200, 'elasticsearch'],
  [11211, 'memcached'],
  [27017, 'mongodb'],
  [27018, 'mongodb'],
  [5672, 'rabbitmq'],
])

/** Админки и служебные порты: открыты наружу — high */
export const ADMIN_PORTS: ReadonlyMap<number, string> = new Map([
  [81, 'nginx proxy manager'],
  [3000, 'dev-сервер'],
  [5000, 'dev-сервер'],
  [8080, 'админка или dev'],
  [8443, 'админка'],
  [9000, 'adminer/php-fpm'],
  [9090, 'prometheus'],
  [5355, 'LLMNR'],
])

export const FIREWALL_PORTS: ReadonlySet<number> = new Set([81, 9000, 8080, 8443])
