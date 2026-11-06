import type { EolEntry } from './os'

// ДАННЫЕ СВЕРИТЬ: 2026-11-06 — сроки из знаний, требуют проверки по официальным таблицам
export interface RuntimeTable {
  name: string
  versions: Record<string, EolEntry>
}

export const NODE_SUPPORT: RuntimeTable = {
  name: 'node',
  versions: {
    '16': { until: '2023-09-11', note: 'сверить' },
    '18': { until: '2025-04-30', note: 'сверить' },
    '20': { until: '2026-04-30', note: 'сверить' },
    '22': { until: '2027-04-30', note: 'сверить' },
    '24': { until: '2028-04-30', note: 'сверить' },
  },
}

export const BUN_SUPPORT: RuntimeTable = {
  name: 'bun',
  versions: {
    '1.0': { until: '2025-03-01', note: 'сверить' },
    '1.1': { until: '2025-09-01', note: 'сверить' },
    '1.2': { until: '2026-01-01', note: 'сверить' },
    '1.3': { until: '2026-06-01', note: 'сверить' },
    '1.4': { until: '2027-01-01', note: 'сверить' },
  },
}

export const PHP_SUPPORT: RuntimeTable = {
  name: 'php',
  versions: {
    '7.4': { until: '2022-11-28', note: 'сверить' },
    '8.0': { until: '2023-11-26', note: 'сверить' },
    '8.1': { until: '2025-12-31', note: 'сверить' },
    '8.2': { until: '2026-12-31', note: 'сверить' },
    '8.3': { until: '2027-12-31', note: 'сверить' },
    '8.4': { until: '2028-12-31', note: 'сверить' },
  },
}

export const PYTHON_SUPPORT: RuntimeTable = {
  name: 'python3',
  versions: {
    '3.8': { until: '2024-10-07', note: 'сверить' },
    '3.9': { until: '2025-10-31', note: 'сверить' },
    '3.10': { until: '2026-10-31', note: 'сверить' },
    '3.11': { until: '2027-10-31', note: 'сверить' },
    '3.12': { until: '2028-10-31', note: 'сверить' },
    '3.13': { until: '2029-10-31', note: 'сверить' },
    '3.14': { until: '2030-10-31', note: 'сверить' },
  },
}

export const POSTGRES_SUPPORT: RuntimeTable = {
  name: 'postgresql',
  versions: {
    '12': { until: '2024-11-21', note: 'сверить' },
    '13': { until: '2025-11-13', note: 'сверить' },
    '14': { until: '2026-11-12', note: 'сверить' },
    '15': { until: '2027-11-11', note: 'сверить' },
    '16': { until: '2028-11-09', note: 'сверить' },
    '17': { until: '2029-11-08', note: 'сверить' },
    '18': { until: '2030-11-13', note: 'сверить' },
  },
}

export const RUNTIME_TABLES: RuntimeTable[] = [
  NODE_SUPPORT,
  BUN_SUPPORT,
  PHP_SUPPORT,
  PYTHON_SUPPORT,
  POSTGRES_SUPPORT,
]
