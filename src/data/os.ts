// Сроки поддержки взяты из знаний и помечены «сверить» — дата сверки ниже
// ДАННЫЕ СВЕРИТЬ: 2026-11-06
export const DATA_CHECKED = '2026-11-06'

export interface EolEntry {
  /** Последний день поддержки, ISO */
  until: string
  /** Пояснение к сроку, требует сверки */
  note?: string
}

/** Ключ — «id:VERSION_ID» из /etc/os-release */
export const OS_SUPPORT: Record<string, EolEntry> = {
  'ubuntu:14.04': { until: '2019-04-30', note: 'сверить' },
  'ubuntu:16.04': { until: '2021-04-30', note: 'сверить' },
  'ubuntu:18.04': { until: '2023-05-31', note: 'сверить' },
  'ubuntu:20.04': { until: '2025-05-31', note: 'сверить' },
  'ubuntu:22.04': { until: '2027-04-30', note: 'сверить' },
  'ubuntu:24.04': { until: '2029-04-25', note: 'сверить' },
  'ubuntu:24.10': { until: '2025-07-10', note: 'сверить' },
  'ubuntu:25.04': { until: '2026-01-15', note: 'сверить' },
  'ubuntu:25.10': { until: '2026-07-15', note: 'сверить' },
  'debian:10': { until: '2024-06-30', note: 'сверить, срок LTS' },
  'debian:11': { until: '2026-08-31', note: 'сверить, срок LTS' },
  'debian:12': { until: '2028-06-30', note: 'сверить, срок LTS' },
  'debian:13': { until: '2030-06-30', note: 'сверить, срок LTS' },
}
