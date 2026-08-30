import api from './axios'
import type { AuthRequest, AuthResponse } from '@/types'

export const authApi = {
  login: (data: AuthRequest) =>
    api.post<AuthResponse>('/auth/login', data).then((r) => r.data),

  logout: (accessToken: string) =>
    api.post<void>('/auth/logout', null, {
      headers: { Authorization: `Bearer ${accessToken}` },
    }),

  refresh: (refreshToken: string) =>
    api.post<AuthResponse>('/auth/refresh', { refreshToken }).then((r) => r.data),
}
