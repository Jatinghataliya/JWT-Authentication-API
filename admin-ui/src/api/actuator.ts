/**
 * actuator.ts — Thin client for Spring Boot Actuator endpoints.
 *
 * Uses a separate axios instance (baseURL = /actuator) so the JWT
 * Authorization interceptor on the main api instance never runs here.
 * Actuator endpoints are public in this project's SecurityConfig.
 *
 * Endpoints used:
 *   GET /actuator/health        — overall + component breakdown
 *   GET /actuator/info          — app name, version, description
 *   GET /actuator/metrics       — list of all available metric names
 *   GET /actuator/metrics/{name} — value + tags for a named metric
 *   GET /actuator/env           — flattened environment properties
 *   GET /actuator/loggers       — list of all loggers + their level
 *   POST /actuator/loggers/{name} — change a logger's level at runtime
 */
import axios from 'axios'

const actuator = axios.create({ baseURL: '/actuator' })

// ─── Types ────────────────────────────────────────────────────────────────────

export interface HealthStatus {
  status: 'UP' | 'DOWN' | 'OUT_OF_SERVICE' | 'UNKNOWN'
  components?: Record<string, { status: string; details?: Record<string, unknown> }>
}

export interface AppInfo {
  app?: {
    name?: string
    description?: string
    version?: string
    'java-version'?: string
  }
  build?: { artifact?: string; version?: string; time?: string }
}

export interface MetricValue {
  name: string
  description: string
  baseUnit: string | null
  measurements: Array<{ statistic: string; value: number }>
  availableTags: Array<{ tag: string; values: string[] }>
}

export interface EnvResponse {
  activeProfiles: string[]
  propertySources: Array<{
    name: string
    properties: Record<string, { value: unknown }>
  }>
}

export interface LoggerInfo {
  configuredLevel: string | null
  effectiveLevel: string
}

export interface LoggersResponse {
  levels: string[]
  loggers: Record<string, LoggerInfo>
}

// ─── API calls ────────────────────────────────────────────────────────────────

export const actuatorApi = {
  health: () =>
    actuator.get<HealthStatus>('/health').then((r) => r.data),

  info: () =>
    actuator.get<AppInfo>('/info').then((r) => r.data),

  metricNames: () =>
    actuator.get<{ names: string[] }>('/metrics').then((r) => r.data.names),

  metric: (name: string) =>
    actuator.get<MetricValue>(`/metrics/${name}`).then((r) => r.data),

  env: () =>
    actuator.get<EnvResponse>('/env').then((r) => r.data),

  loggers: () =>
    actuator.get<LoggersResponse>('/loggers').then((r) => r.data),

  setLogLevel: (loggerName: string, level: string | null) =>
    actuator.post(`/loggers/${loggerName}`, { configuredLevel: level }),
}

// ─── Helper: extract a clean numeric value from a MetricValue ────────────────
export function metricVal(m: MetricValue | undefined, statistic = 'VALUE'): number | null {
  if (!m) return null
  const found = m.measurements.find((s) => s.statistic === statistic)
  return found ? found.value : (m.measurements[0]?.value ?? null)
}

// ─── Key metrics we always want to show ───────────────────────────────────────
export const KEY_METRICS = [
  // JVM
  { name: 'jvm.memory.used',          label: 'JVM Memory Used',     unit: 'MB',  divisor: 1_048_576, statistic: 'VALUE' },
  { name: 'jvm.memory.max',           label: 'JVM Memory Max',      unit: 'MB',  divisor: 1_048_576, statistic: 'VALUE' },
  { name: 'jvm.threads.live',         label: 'Live Threads',        unit: '',    divisor: 1,         statistic: 'VALUE' },
  { name: 'jvm.threads.daemon',       label: 'Daemon Threads',      unit: '',    divisor: 1,         statistic: 'VALUE' },
  { name: 'jvm.classes.loaded',       label: 'Classes Loaded',      unit: '',    divisor: 1,         statistic: 'VALUE' },
  { name: 'process.uptime',           label: 'Uptime',              unit: 's',   divisor: 1,         statistic: 'VALUE' },
  { name: 'process.cpu.usage',        label: 'CPU Usage',           unit: '%',   divisor: 0.01,      statistic: 'VALUE' },
  { name: 'system.cpu.usage',         label: 'System CPU',          unit: '%',   divisor: 0.01,      statistic: 'VALUE' },
  // HTTP
  { name: 'http.server.requests',     label: 'Total HTTP Requests', unit: '',    divisor: 1,         statistic: 'COUNT' },
  { name: 'http.server.requests',     label: 'Avg Response Time',   unit: 'ms',  divisor: 0.001,     statistic: 'TOTAL_TIME' },
] as const
