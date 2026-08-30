import api from './axios'
import type {
  AdminRegisterRequest,
  AssignRoleRequest,
  AuthResponse,
  LoginAttemptSummary,
  PagedResponse,
  UserSummary,
} from '@/types'

export const usersApi = {
  getPaged: (page = 0, size = 20) =>
    api.get<PagedResponse<UserSummary>>(`/admin/users/paged?page=${page}&size=${size}`).then((r) => r.data),

  getById: (id: number) =>
    api.get<UserSummary>(`/admin/users/${id}`).then((r) => r.data),

  create: (data: AdminRegisterRequest) =>
    api.post<AuthResponse>('/admin/users', data).then((r) => r.data),

  delete: (id: number) =>
    api.delete<void>(`/admin/users/${id}`),

  erase: (id: number) =>
    api.delete<void>(`/admin/users/${id}/erase`),

  enable: (id: number) =>
    api.patch<UserSummary>(`/admin/users/${id}/enable`).then((r) => r.data),

  disable: (id: number) =>
    api.patch<UserSummary>(`/admin/users/${id}/disable`).then((r) => r.data),

  lock: (id: number) =>
    api.patch<UserSummary>(`/admin/users/${id}/lock`).then((r) => r.data),

  unlock: (id: number) =>
    api.patch<UserSummary>(`/admin/users/${id}/unlock`).then((r) => r.data),

  assignRole: (id: number, data: AssignRoleRequest) =>
    api.post<UserSummary>(`/admin/users/${id}/roles`, data).then((r) => r.data),

  revokeRole: (id: number, data: AssignRoleRequest) =>
    api.delete<UserSummary>(`/admin/users/${id}/roles`, { data }).then((r) => r.data),

  getLoginAttempts: (id: number) =>
    api.get<LoginAttemptSummary[]>(`/admin/users/${id}/login-attempts`).then((r) => r.data),
}
