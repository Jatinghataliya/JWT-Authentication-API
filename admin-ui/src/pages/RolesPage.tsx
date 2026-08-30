import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import { rolesApi } from '@/api/roles'
import toast from 'react-hot-toast'

export default function RolesPage() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  const { data: roles = [], isLoading } = useQuery({
    queryKey: ['roles'],
    queryFn: rolesApi.getAll,
  })

  const createMutation = useMutation({
    mutationFn: () => rolesApi.create({ name: name.toUpperCase(), description }),
    onSuccess: () => {
      toast.success(`Role "${name.toUpperCase()}" created`)
      setName(''); setDescription('')
      qc.invalidateQueries({ queryKey: ['roles'] })
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Failed'
      toast.error(msg)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => rolesApi.delete(id),
    onSuccess: () => {
      toast.success('Role deleted')
      qc.invalidateQueries({ queryKey: ['roles'] })
    },
    onError: () => toast.error('Failed to delete role'),
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-900">Roles</h1>
        <p className="text-sm text-gray-500 mt-0.5">Manage the role catalog — roles can be assigned to users dynamically.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Create role */}
        <div className="card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-gray-800">Create new role</h2>
          <div>
            <label className="label">Role name</label>
            <input
              className="input uppercase"
              placeholder="e.g. REPORT_VIEWER"
              value={name}
              onChange={(e) => setName(e.target.value.toUpperCase())}
            />
          </div>
          <div>
            <label className="label">Description <span className="font-normal text-gray-400">(optional)</span></label>
            <input
              className="input"
              placeholder="What this role grants…"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
          <button
            className="btn-primary"
            disabled={!name || createMutation.isPending}
            onClick={() => createMutation.mutate()}
          >
            <Plus size={14} />
            {createMutation.isPending ? 'Creating…' : 'Create role'}
          </button>
        </div>

        {/* Role list */}
        <div className="card overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-100">
            <h2 className="text-sm font-semibold text-gray-800">Existing roles ({roles.length})</h2>
          </div>
          {isLoading && <p className="text-sm text-gray-400 p-5">Loading…</p>}
          <ul className="divide-y divide-gray-100">
            {roles.map((r) => (
              <li key={r.id} className="flex items-center justify-between px-5 py-3 hover:bg-gray-50">
                <div>
                  <span className="badge-purple mr-2">{r.name}</span>
                  {r.description && <span className="text-xs text-gray-500">{r.description}</span>}
                </div>
                <button
                  className="btn-ghost btn-sm text-red-500"
                  title="Delete role"
                  onClick={() => deleteMutation.mutate(r.id)}
                >
                  <Trash2 size={13} />
                </button>
              </li>
            ))}
            {!isLoading && roles.length === 0 && (
              <li className="text-sm text-gray-400 px-5 py-6 text-center">No roles found</li>
            )}
          </ul>
        </div>
      </div>
    </div>
  )
}
