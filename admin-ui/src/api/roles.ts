import api from './axios'
import type { RoleRequest, RoleResponse } from '@/types'

export const rolesApi = {
  getAll: () =>
    api.get<RoleResponse[]>('/admin/roles').then((r) => r.data),

  getById: (id: number) =>
    api.get<RoleResponse>(`/admin/roles/${id}`).then((r) => r.data),

  create: (data: RoleRequest) =>
    api.post<RoleResponse>('/admin/roles', data).then((r) => r.data),

  update: (id: number, data: RoleRequest) =>
    api.put<RoleResponse>(`/admin/roles/${id}`, data).then((r) => r.data),

  delete: (id: number) =>
    api.delete<void>(`/admin/roles/${id}`),
}
