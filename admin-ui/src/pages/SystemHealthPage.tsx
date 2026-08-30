import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Activity, Server, Cpu, Layers, Settings2,
  CheckCircle, XCircle, AlertCircle, RefreshCw,
} from 'lucide-react'
import {
  actuatorApi, metricVal, KEY_METRICS,
  type HealthStatus, type MetricValue,
} from '@/api/actuator'
import toast from 'react-hot-toast'
import clsx from 'clsx'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function statusColor(s: string) {
  if (s === 'UP')               return 'text-green-600'
  if (s === 'DOWN')             return 'text-red-600'
  if (s === 'OUT_OF_SERVICE')   return 'text-yellow-600'
  return 'text-gray-500'
}

function StatusDot({ status }: { status: string }) {
  const cls =
    status === 'UP'             ? 'bg-green-500' :
    status === 'DOWN'           ? 'bg-red-500'   :
    status === 'OUT_OF_SERVICE' ? 'bg-yellow-500':
                                   'bg-gray-400'
  return <span className={`inline-block w-2 h-2 rounded-full ${cls} flex-shrink-0`} />
}

function StatusIcon({ status }: { status: string }) {
  if (status === 'UP')   return <CheckCircle size={18} className="text-green-500" />
  if (status === 'DOWN') return <XCircle     size={18} className="text-red-500" />
  return                         <AlertCircle size={18} className="text-yellow-500" />
}

function SectionHeader({ icon: Icon, title, subtitle }: {
  icon: React.ElementType; title: string; subtitle?: string
}) {
  return (
    <div className="px-5 py-4 border-b border-gray-100 flex items-center gap-2">
      <Icon size={16} className="text-gray-400" />
      <h2 className="text-sm font-semibold text-gray-800">{title}</h2>
      {subtitle && <span className="ml-auto text-xs text-gray-400">{subtitle}</span>}
    </div>
  )
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m ${s}s`
  return `${m}m ${s}s`
}

function formatMetricValue(raw: number | null, unit: string, divisor: number): string {
  if (raw === null) return '—'
  const v = raw / divisor
  if (unit === '%') return `${(v * 100).toFixed(1)}%`
  if (unit === 's' && divisor === 1) return formatUptime(v)
  if (Number.isInteger(v)) return `${v.toLocaleString()}${unit ? ' ' + unit : ''}`
  return `${v.toFixed(2)}${unit ? ' ' + unit : ''}`
}

// ─── Section: Overall Health ──────────────────────────────────────────────────

function HealthSection({ health, isLoading }: { health: HealthStatus | undefined; isLoading: boolean }) {
  return (
    <div className="card">
      <SectionHeader icon={Activity} title="Health" subtitle="GET /actuator/health" />
      <div className="p-5">
        {isLoading && <p className="text-sm text-gray-400">Loading…</p>}
        {!isLoading && health && (
          <div className="space-y-4">
            {/* Overall status */}
            <div className="flex items-center gap-3">
              <StatusIcon status={health.status} />
              <span className={clsx('text-lg font-bold', statusColor(health.status))}>
                {health.status}
              </span>
              <span className="text-xs text-gray-400 ml-auto">Overall application status</span>
            </div>

            {/* Component breakdown */}
            {health.components && Object.keys(health.components).length > 0 && (
              <div className="border border-gray-100 rounded-md overflow-hidden">
                <table>
                  <thead>
                    <tr>
                      <th>Component</th>
                      <th>Status</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(health.components).map(([name, comp]) => (
                      <tr key={name}>
                        <td className="font-medium capitalize">{name}</td>
                        <td>
                          <span className="flex items-center gap-1.5">
                            <StatusDot status={comp.status} />
                            <span className={clsx('text-xs font-semibold', statusColor(comp.status))}>
                              {comp.status}
                            </span>
                          </span>
                        </td>
                        <td className="text-gray-400 text-xs max-w-xs">
                          {comp.details
                            ? Object.entries(comp.details)
                                .map(([k, v]) => `${k}: ${JSON.stringify(v)}`)
                                .join(' · ')
                            : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Section: App Info ────────────────────────────────────────────────────────

function InfoSection({ info, isLoading }: { info: ReturnType<typeof Object.entries> | undefined; isLoading: boolean }) {
  return (
    <div className="card">
      <SectionHeader icon={Server} title="Application Info" subtitle="GET /actuator/info" />
      <div className="p-5">
        {isLoading && <p className="text-sm text-gray-400">Loading…</p>}
        {!isLoading && info && (
          <dl className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm">
            {info.map(([key, value]) => (
              <div key={key}>
                <dt className="text-xs text-gray-400 capitalize">{key.replace(/-/g, ' ')}</dt>
                <dd className="font-medium text-gray-800 mt-0.5">{String(value)}</dd>
              </div>
            ))}
          </dl>
        )}
        {!isLoading && (!info || info.length === 0) && (
          <p className="text-sm text-gray-400">No info properties configured.</p>
        )}
      </div>
    </div>
  )
}

// ─── Section: JVM + Process Metrics ──────────────────────────────────────────

type MetricDef = { name: string; label: string; unit: string; divisor: number; statistic: string }

function MetricsGrid({ metrics }: { metrics: Map<string, MetricValue | undefined> }) {
  const jvmKeys: MetricDef[] = (KEY_METRICS as unknown as MetricDef[]).filter((m) =>
    ['jvm.', 'process.', 'system.'].some((p) => m.name.startsWith(p)),
  )
  const httpKeys: MetricDef[] = (KEY_METRICS as unknown as MetricDef[]).filter((m) =>
    m.name.startsWith('http.'),
  )

  function renderGroup(keys: MetricDef[], title: string, icon: React.ElementType) {
    const Icon = icon
    return (
      <div className="card">
        <SectionHeader icon={Icon} title={title} subtitle="GET /actuator/metrics/{name}" />
        <div className="p-5">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
            {keys.map((m) => {
              const data = metrics.get(`${m.name}::${m.statistic}`)
              const raw = metricVal(data, m.statistic)
              return (
                <div key={`${m.name}-${m.statistic}-${m.label}`}
                  className="bg-gray-50 rounded-lg p-3 border border-gray-100">
                  <p className="text-lg font-bold text-gray-900 leading-none">
                    {formatMetricValue(raw, m.unit, m.divisor)}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">{m.label}</p>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    )
  }

  return (
    <>
      {renderGroup(jvmKeys, 'JVM & Process Metrics', Cpu)}
      {renderGroup(httpKeys, 'HTTP Request Metrics', Activity)}
    </>
  )
}

// ─── Section: Loggers ─────────────────────────────────────────────────────────

const LOG_LEVELS = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'OFF', 'RESET']

const LEVEL_COLOR: Record<string, string> = {
  TRACE: 'badge-gray',
  DEBUG: 'badge-blue',
  INFO:  'badge-green',
  WARN:  'badge-yellow',
  ERROR: 'badge-red',
  OFF:   'badge-gray',
}

function LoggersSection() {
  const qc = useQueryClient()
  const [filter, setFilter] = useState('')
  const [expandedLogger, setExpandedLogger] = useState<string | null>(null)

  const { data: loggersData, isLoading } = useQuery({
    queryKey: ['actuator-loggers'],
    queryFn: actuatorApi.loggers,
    staleTime: 10_000,
  })

  const setLevelMutation = useMutation({
    mutationFn: ({ name, level }: { name: string; level: string }) =>
      actuatorApi.setLogLevel(name, level === 'RESET' ? null : level),
    onSuccess: (_, { name, level }) => {
      toast.success(`${name} → ${level}`)
      qc.invalidateQueries({ queryKey: ['actuator-loggers'] })
      setExpandedLogger(null)
    },
    onError: () => toast.error('Failed to change log level'),
  })

  const loggers = loggersData?.loggers ?? {}
  const filtered = Object.entries(loggers).filter(
    ([name]) => !filter || name.toLowerCase().includes(filter.toLowerCase()),
  )
  // Show root + project loggers first, then all others
  const prioritised = [
    ...filtered.filter(([n]) => n === 'ROOT' || n.startsWith('com.jatin')),
    ...filtered.filter(([n]) => n !== 'ROOT' && !n.startsWith('com.jatin')),
  ]

  return (
    <div className="card">
      <SectionHeader icon={Settings2} title="Log Levels" subtitle="GET /actuator/loggers — click a row to change" />
      <div className="px-5 py-3 border-b border-gray-100">
        <input
          className="input max-w-xs"
          placeholder="Filter by logger name…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      <div className="overflow-x-auto max-h-80 overflow-y-auto">
        {isLoading && <p className="text-sm text-gray-400 p-5">Loading…</p>}
        <table>
          <thead className="sticky top-0 z-10">
            <tr>
              <th>Logger</th>
              <th>Configured</th>
              <th>Effective</th>
            </tr>
          </thead>
          <tbody>
            {prioritised.map(([name, info]) => (
              <>
                <tr
                  key={name}
                  className="cursor-pointer"
                  onClick={() => setExpandedLogger(expandedLogger === name ? null : name)}
                >
                  <td className="font-mono text-xs">{name}</td>
                  <td>
                    <span className={LEVEL_COLOR[info.configuredLevel ?? ''] ?? 'badge-gray'}>
                      {info.configuredLevel ?? 'inherited'}
                    </span>
                  </td>
                  <td>
                    <span className={LEVEL_COLOR[info.effectiveLevel] ?? 'badge-gray'}>
                      {info.effectiveLevel}
                    </span>
                  </td>
                </tr>
                {expandedLogger === name && (
                  <tr key={`${name}-expand`} className="bg-blue-50">
                    <td colSpan={3} className="px-4 py-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs text-gray-500 mr-1">Set level:</span>
                        {LOG_LEVELS.map((level) => (
                          <button
                            key={level}
                            className={clsx(
                              'btn btn-sm border transition-colors',
                              level === 'RESET'
                                ? 'bg-white border-gray-300 text-gray-600 hover:bg-gray-50'
                                : level === info.effectiveLevel
                                ? 'bg-blue-600 text-white border-blue-600'
                                : 'bg-white border-gray-300 text-gray-600 hover:border-blue-400',
                            )}
                            disabled={setLevelMutation.isPending}
                            onClick={(e) => { e.stopPropagation(); setLevelMutation.mutate({ name, level }) }}
                          >
                            {level}
                          </button>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {!isLoading && prioritised.length === 0 && (
              <tr><td colSpan={3} className="text-center text-gray-400 py-6">No loggers match</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SystemHealthPage() {
  const qc = useQueryClient()

  const { data: health, isLoading: healthLoading } = useQuery({
    queryKey: ['actuator-health'],
    queryFn: actuatorApi.health,
    refetchInterval: 30_000,   // auto-refresh every 30 s
    staleTime: 10_000,
  })

  const { data: info, isLoading: infoLoading } = useQuery({
    queryKey: ['actuator-info'],
    queryFn: actuatorApi.info,
    staleTime: 60_000,
  })

  // Fetch all KEY_METRICS in one batch — deduplicate by name
  const uniqueMetricNames = [...new Set(KEY_METRICS.map((m) => m.name))]
  const metricQueries = useQuery({
    queryKey: ['actuator-metrics-batch'],
    queryFn: async () => {
      const results = await Promise.allSettled(
        uniqueMetricNames.map((n) => actuatorApi.metric(n)),
      )
      const map = new Map<string, MetricValue>()
      results.forEach((r, i) => {
        if (r.status === 'fulfilled') map.set(uniqueMetricNames[i], r.value)
      })
      return map
    },
    refetchInterval: 15_000,
    staleTime: 10_000,
  })

  // Expand the map to include per-statistic keys used by MetricsGrid
  const metricsMap = new Map<string, MetricValue | undefined>()
  if (metricQueries.data) {
    KEY_METRICS.forEach((m) => {
      metricsMap.set(`${m.name}::${m.statistic}`, metricQueries.data.get(m.name))
    })
  }

  // Flatten info object to key-value pairs for display
  const infoEntries = info
    ? Object.entries(info.app ?? {}).map(([k, v]) => [k, v])
    : []

  function refresh() {
    qc.invalidateQueries({ queryKey: ['actuator-health'] })
    qc.invalidateQueries({ queryKey: ['actuator-metrics-batch'] })
    qc.invalidateQueries({ queryKey: ['actuator-loggers'] })
    toast.success('Refreshed')
  }

  const overallStatus = health?.status ?? 'UNKNOWN'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">System Health</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Live data from Spring Boot Actuator — auto-refreshes every 15–30 s
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Quick status pill */}
          <span className={clsx(
            'inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border',
            overallStatus === 'UP'
              ? 'bg-green-50 border-green-200 text-green-700'
              : overallStatus === 'DOWN'
              ? 'bg-red-50 border-red-200 text-red-700'
              : 'bg-yellow-50 border-yellow-200 text-yellow-700',
          )}>
            <StatusDot status={overallStatus} />
            {overallStatus}
          </span>
          <button className="btn-secondary btn-sm" onClick={refresh}>
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {/* Health */}
      <HealthSection health={health} isLoading={healthLoading} />

      {/* App Info */}
      <InfoSection info={infoEntries as [string, string][]} isLoading={infoLoading} />

      {/* JVM + HTTP Metrics */}
      <MetricsGrid metrics={metricsMap} />

      {/* Log Levels */}
      <LoggersSection />
    </div>
  )
}
