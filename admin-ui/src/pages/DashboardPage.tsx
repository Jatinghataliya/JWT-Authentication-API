import { useQuery } from '@tanstack/react-query'
import { Users, ShieldCheck, Lock, Trash2, Activity } from 'lucide-react'
import { usersApi } from '@/api/users'
import { auditApi } from '@/api/audit'
import type { UserSummary } from '@/types'

function StatCard({ label, value, icon: Icon, color }: {
  label: string; value: number | string; icon: React.ElementType; color: string
}) {
  return (
    <div className="card p-5 flex items-center gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${color}`}>
        <Icon size={18} className="text-white" />
      </div>
      <div>
        <p className="text-2xl font-bold text-gray-900 leading-none">{value}</p>
        <p className="text-xs text-gray-500 mt-1">{label}</p>
      </div>
    </div>
  )
}

function computeStats(users: UserSummary[]) {
  return {
    total:   users.length,
    active:  users.filter((u) => u.enabled && u.accountNonLocked && !u.deletedAt).length,
    locked:  users.filter((u) => !u.accountNonLocked).length,
    erased:  users.filter((u) => !!u.deletedAt).length,
  }
}

export default function DashboardPage() {
  const { data: usersPage } = useQuery({
    queryKey: ['users', 0, 200],
    queryFn: () => usersApi.getPaged(0, 200),
  })

  const { data: auditPage } = useQuery({
    queryKey: ['audit', undefined, 0, 10],
    queryFn: () => auditApi.getPaged(undefined, 0, 10),
  })

  const stats = usersPage ? computeStats(usersPage.content) : null

  const eventColors: Record<string, string> = {
    LOGIN_SUCCESS: 'badge-green',
    LOGIN_FAILURE: 'badge-red',
    REGISTER: 'badge-blue',
    LOGOUT: 'badge-gray',
    ACCOUNT_LOCKED: 'badge-yellow',
    ACCOUNT_ERASED: 'badge-red',
    ACCOUNT_DELETION_REQUESTED: 'badge-yellow',
    ACCOUNT_DISABLED: 'badge-yellow',
    ACCOUNT_ENABLED: 'badge-green',
    ACCOUNT_UNLOCKED: 'badge-green',
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-0.5">Overview of your JWT Authentication system</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total users"    value={stats?.total ?? '—'} icon={Users}       color="bg-blue-500" />
        <StatCard label="Active accounts" value={stats?.active ?? '—'} icon={ShieldCheck} color="bg-green-500" />
        <StatCard label="Locked accounts" value={stats?.locked ?? '—'} icon={Lock}        color="bg-yellow-500" />
        <StatCard label="Erased accounts" value={stats?.erased ?? '—'} icon={Trash2}      color="bg-red-500" />
      </div>

      {/* Recent audit events */}
      <div className="card">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center gap-2">
          <Activity size={16} className="text-gray-400" />
          <h2 className="text-sm font-semibold text-gray-800">Recent Audit Events</h2>
          <span className="ml-auto text-xs text-gray-400">Latest 10</span>
        </div>
        <div className="overflow-x-auto">
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Event</th>
                <th>IP Address</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {auditPage?.content.map((e) => (
                <tr key={e.id}>
                  <td className="font-medium">{e.username}</td>
                  <td>
                    <span className={eventColors[e.eventType] ?? 'badge-gray'}>
                      {e.eventType}
                    </span>
                  </td>
                  <td className="text-gray-400">{e.ipAddress ?? '—'}</td>
                  <td className="text-gray-400 whitespace-nowrap">
                    {new Date(e.createdAt).toLocaleString()}
                  </td>
                </tr>
              ))}
              {!auditPage?.content.length && (
                <tr><td colSpan={4} className="text-center text-gray-400 py-6">No events yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
