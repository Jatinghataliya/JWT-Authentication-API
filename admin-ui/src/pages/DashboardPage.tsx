import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Users, ShieldCheck, Lock, Trash2, Activity, HeartPulse, KeyRound, Check, X } from 'lucide-react'
import { usersApi } from '@/api/users'
import { auditApi } from '@/api/audit'
import { actuatorApi } from '@/api/actuator'
import api from '@/api/axios'
import { Link } from 'react-router-dom'
import type { UserSummary } from '@/types'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { useState } from 'react'

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

// ─── Password Policy types & API ──────────────────────────────────────────────
interface PasswordPolicy {
  minLength: number
  requireUppercase: boolean
  requireDigit: boolean
  requireSpecialChar: boolean
  expiryDays: number
}

const policyApi = {
  get: () => api.get<PasswordPolicy>('/admin/settings/password-policy').then(r => r.data),
  update: (p: PasswordPolicy) => api.put<PasswordPolicy>('/admin/settings/password-policy', p).then(r => r.data),
}

// ─── Password Policy Card ─────────────────────────────────────────────────────
function PasswordPolicyCard() {
  const qc = useQueryClient()
  const { data: policy, isLoading } = useQuery({
    queryKey: ['password-policy'],
    queryFn: policyApi.get,
    staleTime: 30_000,
  })
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<PasswordPolicy | null>(null)

  function startEdit() {
    if (policy) { setDraft({ ...policy }); setEditing(true) }
  }

  const saveMutation = useMutation({
    mutationFn: (p: PasswordPolicy) => policyApi.update(p),
    onSuccess: () => {
      toast.success('Password policy updated')
      qc.invalidateQueries({ queryKey: ['password-policy'] })
      setEditing(false)
    },
    onError: () => toast.error('Failed to update policy'),
  })

  const current = editing && draft ? draft : policy

  return (
    <div className="card">
      <div className="px-5 py-4 border-b border-gray-100 flex items-center gap-2">
        <KeyRound size={16} className="text-gray-400" />
        <h2 className="text-sm font-semibold text-gray-800">Password Policy</h2>
        <span className="ml-auto flex gap-2">
          {editing ? (
            <>
              <button className="btn-secondary btn-sm" onClick={() => setEditing(false)}>Cancel</button>
              <button className="btn-primary btn-sm" disabled={saveMutation.isPending}
                onClick={() => draft && saveMutation.mutate(draft)}>
                {saveMutation.isPending ? 'Saving…' : 'Save'}
              </button>
            </>
          ) : (
            <button className="btn-secondary btn-sm" onClick={startEdit} disabled={isLoading}>Edit</button>
          )}
        </span>
      </div>
      <div className="p-5">
        {isLoading && <p className="text-sm text-gray-400">Loading…</p>}
        {current && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Min Length */}
            <div className="flex items-center justify-between bg-gray-50 rounded-lg px-4 py-3 border border-gray-100">
              <span className="text-sm text-gray-600">Min Length</span>
              {editing && draft ? (
                <input type="number" min={1} max={128}
                  className="input w-20 text-right py-1 text-sm"
                  value={draft.minLength}
                  onChange={e => setDraft({ ...draft, minLength: Math.max(1, +e.target.value) })} />
              ) : (
                <span className="font-bold text-gray-900">{current.minLength} chars</span>
              )}
            </div>

            {/* Expiry Days */}
            <div className="flex items-center justify-between bg-gray-50 rounded-lg px-4 py-3 border border-gray-100">
              <span className="text-sm text-gray-600">Expiry</span>
              {editing && draft ? (
                <div className="flex items-center gap-1">
                  <input type="number" min={0}
                    className="input w-20 text-right py-1 text-sm"
                    value={draft.expiryDays}
                    onChange={e => setDraft({ ...draft, expiryDays: Math.max(0, +e.target.value) })} />
                  <span className="text-xs text-gray-400">days</span>
                </div>
              ) : (
                <span className="font-bold text-gray-900">
                  {current.expiryDays === 0 ? 'Never' : `${current.expiryDays} days`}
                </span>
              )}
            </div>

            {/* Boolean toggles */}
            {([
              { key: 'requireUppercase',   label: 'Uppercase letter' },
              { key: 'requireDigit',        label: 'Digit (0–9)' },
              { key: 'requireSpecialChar',  label: 'Special character' },
            ] as { key: keyof PasswordPolicy; label: string }[]).map(({ key, label }) => (
              <div key={key}
                className="flex items-center justify-between bg-gray-50 rounded-lg px-4 py-3 border border-gray-100">
                <span className="text-sm text-gray-600">{label}</span>
                {editing && draft ? (
                  <button type="button"
                    className={clsx('w-10 h-5 rounded-full transition-colors relative',
                      draft[key] ? 'bg-blue-500' : 'bg-gray-300')}
                    onClick={() => setDraft({ ...draft, [key]: !draft[key] })}>
                    <span className={clsx('absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-all',
                      draft[key] ? 'left-5' : 'left-0.5')} />
                  </button>
                ) : (
                  current[key]
                    ? <Check size={16} className="text-green-600" />
                    : <X    size={16} className="text-gray-300" />
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
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

  const { data: health } = useQuery({
    queryKey: ['actuator-health'],
    queryFn: actuatorApi.health,
    refetchInterval: 30_000,
    staleTime: 10_000,
  })

  const stats = usersPage ? computeStats(usersPage.content) : null

  const healthColor =
    health?.status === 'UP'   ? 'bg-green-500' :
    health?.status === 'DOWN' ? 'bg-red-500'   :
                                 'bg-yellow-500'

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
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard label="Total users"     value={stats?.total  ?? '—'} icon={Users}       color="bg-blue-500" />
        <StatCard label="Active accounts" value={stats?.active ?? '—'} icon={ShieldCheck} color="bg-green-500" />
        <StatCard label="Locked accounts" value={stats?.locked ?? '—'} icon={Lock}        color="bg-yellow-500" />
        <StatCard label="Erased accounts" value={stats?.erased ?? '—'} icon={Trash2}      color="bg-red-500" />
        {/* Health quick-glance — links to System Health page */}
        <Link to="/system-health" className="card p-5 flex items-center gap-4 hover:border-blue-300 transition-colors">
          <div className={clsx('w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0', healthColor)}>
            <HeartPulse size={18} className="text-white" />
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900 leading-none">
              {health?.status ?? '—'}
            </p>
            <p className="text-xs text-gray-500 mt-1">App Health →</p>
          </div>
        </Link>
      </div>

      {/* Password Policy */}
      <PasswordPolicyCard />

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
