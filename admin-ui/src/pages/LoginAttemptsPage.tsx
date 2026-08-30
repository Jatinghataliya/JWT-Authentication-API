import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Search, Lock } from 'lucide-react'
import { usersApi } from '@/api/users'
import toast from 'react-hot-toast'

export default function LoginAttemptsPage() {
  const qc = useQueryClient()
  const [searchInput, setSearchInput] = useState('')
  const [activeUsername, setActiveUsername] = useState('')
  const [userId, setUserId] = useState<number | null>(null)

  // Fetch login attempts only when a userId is selected
  const { data: attempts, isLoading } = useQuery({
    queryKey: ['attempts', userId],
    queryFn: () => usersApi.getLoginAttempts(userId!),
    enabled: userId !== null,
  })

  const lockMutation = useMutation({
    mutationFn: () => usersApi.lock(userId!),
    onSuccess: () => { toast.success(`${activeUsername} locked`); qc.invalidateQueries({ queryKey: ['users'] }) },
    onError: () => toast.error('Lock failed'),
  })

  async function doSearch() {
    const trimmed = searchInput.trim()
    if (!trimmed) return
    try {
      // Use server-side search by exact username
      const result = await usersApi.search({ username: trimmed, size: 50 })
      const found = result.content.find(
        (u) => u.username.toLowerCase() === trimmed.toLowerCase(),
      )
      if (!found) {
        toast.error(`User "${trimmed}" not found`)
        return
      }
      setActiveUsername(found.username)
      setUserId(found.id)
    } catch {
      toast.error('Failed to search for user')
    }
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold text-gray-900">Login Attempts</h1>
        <p className="text-sm text-gray-500 mt-0.5">Last 20 login attempts for any user</p>
      </div>

      {/* Search */}
      <div className="flex gap-2 max-w-sm">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            className="input pl-8"
            placeholder="Enter username…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && doSearch()}
          />
        </div>
        <button className="btn-primary" onClick={doSearch}>Look up</button>
      </div>

      {/* Result header */}
      {activeUsername && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-700">
            Showing attempts for <span className="font-semibold">{activeUsername}</span>
          </p>
          <button
            className="btn-danger btn-sm"
            onClick={() => lockMutation.mutate()}
            disabled={lockMutation.isPending}
          >
            <Lock size={13} /> Lock account
          </button>
        </div>
      )}

      {/* Table */}
      {userId !== null && (
        <div className="card overflow-x-auto">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Result</th>
                <th>IP Address</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={3} className="text-center text-gray-400 py-8">Loading…</td></tr>
              )}
              {!isLoading && attempts?.length === 0 && (
                <tr><td colSpan={3} className="text-center text-gray-400 py-8">No attempts recorded</td></tr>
              )}
              {attempts?.map((a) => (
                <tr key={a.id}>
                  <td className="whitespace-nowrap text-gray-500">
                    {new Date(a.attemptedAt).toLocaleString()}
                  </td>
                  <td>
                    {a.success
                      ? <span className="badge-green">Success</span>
                      : <span className="badge-red">Failure</span>}
                  </td>
                  <td className="text-gray-400">{a.ipAddress ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {userId === null && (
        <div className="card p-10 text-center text-gray-400 text-sm">
          Enter a username above to view their login history
        </div>
      )}
    </div>
  )
}
