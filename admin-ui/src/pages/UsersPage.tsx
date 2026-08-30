import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, ChevronLeft, ChevronRight, Lock, Unlock,
  UserX, UserCheck, Trash2, ShieldOff, Search, Download, X,
} from 'lucide-react'
import { usersApi } from '@/api/users'
import { rolesApi } from '@/api/roles'
import type { UserSearchParams, UserSummary } from '@/types'
import toast from 'react-hot-toast'
import clsx from 'clsx'

// ─── Status badge ─────────────────────────────────────────────────────────────
function UserStatusBadge({ user }: { user: UserSummary }) {
  if (user.deletedAt)             return <span className="badge-red">Erased</span>
  if (user.deletionRequestedAt)   return <span className="badge-yellow">Pending erase</span>
  if (!user.accountNonLocked)     return <span className="badge-yellow">Locked</span>
  if (!user.enabled)              return <span className="badge-red">Disabled</span>
  return <span className="badge-green">Active</span>
}

// ─── Create user modal ────────────────────────────────────────────────────────
function CreateUserModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const { data: roles = [] } = useQuery({ queryKey: ['roles'], queryFn: rolesApi.getAll })
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [selectedRoles, setSelectedRoles] = useState<string[]>(['USER'])

  const mutation = useMutation({
    mutationFn: () => usersApi.create({ username, password, roles: selectedRoles }),
    onSuccess: () => {
      toast.success(`User "${username}" created`)
      qc.invalidateQueries({ queryKey: ['users'] })
      onClose()
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Failed to create user'
      toast.error(msg)
    },
  })

  function toggleRole(name: string) {
    setSelectedRoles((prev) =>
      prev.includes(name) ? prev.filter((r) => r !== name) : [...prev, name],
    )
  }

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-md p-6 space-y-4">
        <h2 className="text-base font-semibold text-gray-900">Create User</h2>
        <div>
          <label className="label">Username</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="john_doe" />
        </div>
        <div>
          <label className="label">Password</label>
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="min 6 characters" />
        </div>
        <div>
          <label className="label">Roles</label>
          <div className="flex flex-wrap gap-2">
            {roles.map((r) => (
              <button key={r.id} type="button" onClick={() => toggleRole(r.name)}
                className={clsx('px-3 py-1 rounded-full text-xs font-medium border transition-colors',
                  selectedRoles.includes(r.name)
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400')}>
                {r.name}
              </button>
            ))}
          </div>
        </div>
        <div className="flex gap-2 pt-2">
          <button className="btn-secondary flex-1 justify-center" onClick={onClose}>Cancel</button>
          <button className="btn-primary flex-1 justify-center"
            onClick={() => mutation.mutate()}
            disabled={!username || !password || selectedRoles.length === 0 || mutation.isPending}>
            {mutation.isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Confirm dialog ───────────────────────────────────────────────────────────
function ConfirmDialog({ message, onConfirm, onCancel, danger = false }: {
  message: string; onConfirm: () => void; onCancel: () => void; danger?: boolean
}) {
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-sm p-6 space-y-4">
        <p className="text-sm text-gray-700">{message}</p>
        <div className="flex gap-2">
          <button className="btn-secondary flex-1 justify-center" onClick={onCancel}>Cancel</button>
          <button className={clsx('flex-1 justify-center', danger ? 'btn-danger' : 'btn-primary')} onClick={onConfirm}>
            Confirm
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function UsersPage() {
  const qc = useQueryClient()

  // ── Search / filter state ──────────────────────────────────────────────────
  const [username, setUsername]         = useState('')
  const [email, setEmail]               = useState('')
  const [role, setRole]                 = useState('')
  const [enabled, setEnabled]           = useState<'all' | 'true' | 'false'>('all')
  const [locked, setLocked]             = useState<'all' | 'true' | 'false'>('all')
  const [page, setPage]                 = useState(0)
  const [showCreate, setShowCreate]     = useState(false)
  const [confirm, setConfirm]           = useState<{ msg: string; fn: () => void; danger?: boolean } | null>(null)

  // Derive the params object used for both search query and CSV export
  const searchParams: UserSearchParams = {
    username:         username  || undefined,
    email:            email     || undefined,
    role:             role      || undefined,
    enabled:          enabled  === 'all' ? undefined : enabled  === 'true',
    accountNonLocked: locked   === 'all' ? undefined : locked   === 'false' ? false : undefined,
    page,
    size: 20,
  }

  // Reset to page 0 whenever any filter changes
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const resetPage = useCallback(() => setPage(0), [])
  useEffect(() => { resetPage() }, [username, email, role, enabled, locked, resetPage])

  const hasFilters = !!(username || email || role || enabled !== 'all' || locked !== 'all')

  const { data: rolesData = [] } = useQuery({ queryKey: ['roles'], queryFn: rolesApi.getAll })

  const { data, isLoading } = useQuery({
    queryKey: ['users', 'search', searchParams],
    queryFn: () => usersApi.search(searchParams),
    placeholderData: (prev) => prev,
  })

  function clearFilters() {
    setUsername(''); setEmail(''); setRole('')
    setEnabled('all'); setLocked('all'); setPage(0)
  }

  function handleExportCsv() {
    const url = usersApi.exportCsvUrl(searchParams)
    window.open(url, '_blank')
  }

  function mutate(fn: () => Promise<unknown>, successMsg: string) {
    fn()
      .then(() => { toast.success(successMsg); qc.invalidateQueries({ queryKey: ['users'] }) })
      .catch((err: unknown) => {
        const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Operation failed'
        toast.error(msg)
      })
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Users</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {data?.totalElements ?? 0} {hasFilters ? 'matching' : 'total'} accounts
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary flex items-center gap-1.5" onClick={handleExportCsv}
            title="Export current search results as CSV">
            <Download size={14} /> Export CSV
          </button>
          <button className="btn-primary" onClick={() => setShowCreate(true)}>
            <Plus size={15} /> New user
          </button>
        </div>
      </div>

      {/* Search + filter bar */}
      <div className="card p-4 space-y-3">
        <div className="flex flex-wrap gap-3">
          {/* Username */}
          <div className="relative flex-1 min-w-[160px]">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input className="input pl-8 text-sm" placeholder="Search username…"
              value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>

          {/* Email */}
          <div className="relative flex-1 min-w-[160px]">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input className="input pl-8 text-sm" placeholder="Search email…"
              value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>

          {/* Role */}
          <select className="input text-sm flex-none w-36"
            value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">All roles</option>
            {rolesData.map((r) => (
              <option key={r.id} value={r.name}>{r.name}</option>
            ))}
          </select>

          {/* Enabled status */}
          <select className="input text-sm flex-none w-36"
            value={enabled} onChange={(e) => setEnabled(e.target.value as 'all' | 'true' | 'false')}>
            <option value="all">Any status</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>

          {/* Lock status */}
          <select className="input text-sm flex-none w-36"
            value={locked} onChange={(e) => setLocked(e.target.value as 'all' | 'true' | 'false')}>
            <option value="all">Any lock</option>
            <option value="false">Locked</option>
          </select>

          {/* Clear filters */}
          {hasFilters && (
            <button className="btn-secondary btn-sm flex items-center gap-1" onClick={clearFilters}>
              <X size={13} /> Clear
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-x-auto">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Roles</th>
              <th>Status</th>
              <th>Joined</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={6} className="text-center text-gray-400 py-8">Loading…</td></tr>
            )}
            {!isLoading && (data?.content ?? []).length === 0 && (
              <tr><td colSpan={6} className="text-center text-gray-400 py-8">No users found</td></tr>
            )}
            {(data?.content ?? []).map((u) => (
              <tr key={u.id}>
                <td className="font-medium">{u.username}</td>
                <td className="text-gray-500">{u.email ?? <span className="text-gray-300">—</span>}</td>
                <td>
                  <div className="flex flex-wrap gap-1">
                    {u.roles.map((r) => <span key={r} className="badge-purple">{r}</span>)}
                  </div>
                </td>
                <td><UserStatusBadge user={u} /></td>
                <td className="text-gray-400 whitespace-nowrap">
                  {new Date(u.createdAt).toLocaleDateString()}
                </td>
                <td>
                  <div className="flex items-center gap-1 flex-wrap">
                    {u.enabled ? (
                      <button title="Disable" className="btn-ghost btn-sm text-yellow-600"
                        onClick={() => mutate(() => usersApi.disable(u.id), `${u.username} disabled`)}>
                        <UserX size={13} />
                      </button>
                    ) : (
                      <button title="Enable" className="btn-ghost btn-sm text-green-600"
                        onClick={() => mutate(() => usersApi.enable(u.id), `${u.username} enabled`)}>
                        <UserCheck size={13} />
                      </button>
                    )}
                    {u.accountNonLocked ? (
                      <button title="Lock" className="btn-ghost btn-sm text-yellow-600"
                        onClick={() => mutate(() => usersApi.lock(u.id), `${u.username} locked`)}>
                        <Lock size={13} />
                      </button>
                    ) : (
                      <button title="Unlock" className="btn-ghost btn-sm text-green-600"
                        onClick={() => mutate(() => usersApi.unlock(u.id), `${u.username} unlocked`)}>
                        <Unlock size={13} />
                      </button>
                    )}
                    <button title="GDPR Erase" className="btn-ghost btn-sm text-red-500"
                      onClick={() => setConfirm({
                        msg: `Permanently erase all PII for "${u.username}"? This cannot be undone.`,
                        danger: true,
                        fn: () => mutate(() => usersApi.erase(u.id), `${u.username} erased`),
                      })}>
                      <ShieldOff size={13} />
                    </button>
                    <button title="Delete" className="btn-ghost btn-sm text-red-500"
                      onClick={() => setConfirm({
                        msg: `Permanently delete user "${u.username}"?`,
                        danger: true,
                        fn: () => mutate(() => usersApi.delete(u.id), `${u.username} deleted`),
                      })}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>Page {data.page + 1} of {data.totalPages} ({data.totalElements} results)</span>
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

      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} />}
      {confirm && (
        <ConfirmDialog
          message={confirm.msg}
          danger={confirm.danger}
          onConfirm={() => { confirm.fn(); setConfirm(null) }}
          onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  )
}
