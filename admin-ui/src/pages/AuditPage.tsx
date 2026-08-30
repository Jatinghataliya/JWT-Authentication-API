import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, Search } from 'lucide-react'
import { auditApi } from '@/api/audit'

const EVENT_COLORS: Record<string, string> = {
  LOGIN_SUCCESS:              'badge-green',
  LOGIN_FAILURE:              'badge-red',
  REGISTER:                   'badge-blue',
  LOGOUT:                     'badge-gray',
  ACCOUNT_LOCKED:             'badge-yellow',
  ACCOUNT_UNLOCKED:           'badge-green',
  ACCOUNT_DISABLED:           'badge-yellow',
  ACCOUNT_ENABLED:            'badge-green',
  ACCOUNT_DELETED:            'badge-red',
  ACCOUNT_DELETION_REQUESTED: 'badge-yellow',
  ACCOUNT_ERASED:             'badge-red',
  PASSWORD_RESET_REQUESTED:   'badge-blue',
  PASSWORD_RESET_COMPLETED:   'badge-green',
}

export default function AuditPage() {
  const [page, setPage] = useState(0)
  const [usernameFilter, setUsernameFilter] = useState('')
  const [activeFilter, setActiveFilter] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['audit', activeFilter, page],
    queryFn: () => auditApi.getPaged(activeFilter || undefined, page, 20),
  })

  function applySearch() {
    setActiveFilter(usernameFilter.trim())
    setPage(0)
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold text-gray-900">Audit Log</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Security events recorded system-wide — {data?.totalElements ?? 0} total
        </p>
      </div>

      {/* Filter */}
      <div className="flex gap-2 max-w-sm">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            className="input pl-8"
            placeholder="Filter by username…"
            value={usernameFilter}
            onChange={(e) => setUsernameFilter(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && applySearch()}
          />
        </div>
        <button className="btn-secondary" onClick={applySearch}>Filter</button>
        {activeFilter && (
          <button className="btn-ghost text-gray-500" onClick={() => { setActiveFilter(''); setUsernameFilter(''); setPage(0) }}>
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div className="card overflow-x-auto">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Event</th>
              <th>IP Address</th>
              <th>Details</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={5} className="text-center text-gray-400 py-8">Loading…</td></tr>
            )}
            {!isLoading && data?.content.length === 0 && (
              <tr><td colSpan={5} className="text-center text-gray-400 py-8">No events found</td></tr>
            )}
            {data?.content.map((e) => (
              <tr key={e.id}>
                <td className="font-medium">{e.username}</td>
                <td>
                  <span className={EVENT_COLORS[e.eventType] ?? 'badge-gray'}>
                    {e.eventType}
                  </span>
                </td>
                <td className="text-gray-400">{e.ipAddress ?? '—'}</td>
                <td className="text-gray-500 max-w-xs truncate">{e.details ?? '—'}</td>
                <td className="text-gray-400 whitespace-nowrap">
                  {new Date(e.createdAt).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>Page {data.page + 1} of {data.totalPages}</span>
          <div className="flex gap-2">
            <button className="btn-secondary btn-sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              <ChevronLeft size={14} /> Prev
            </button>
            <button className="btn-secondary btn-sm" disabled={data.last} onClick={() => setPage((p) => p + 1)}>
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
