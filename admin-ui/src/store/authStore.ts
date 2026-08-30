import { create } from 'zustand'

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  username: string | null
  roles: string[]
  isAdmin: boolean

  setTokens: (accessToken: string, refreshToken: string) => void
  setUser: (username: string, roles: string[]) => void
  logout: () => void
}

/**
 * Zustand auth store — access token is kept in JS memory only (never localStorage).
 * This protects against XSS attacks that could steal tokens from localStorage.
 *
 * The refresh token is stored here in memory too; in a hardened production setup
 * you'd use an HttpOnly cookie instead so JS cannot read it at all.
 */
export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  refreshToken: null,
  username: null,
  roles: [],
  isAdmin: false,

  setTokens: (accessToken, refreshToken) =>
    set({ accessToken, refreshToken }),

  setUser: (username, roles) =>
    set({ username, roles, isAdmin: roles.includes('ADMIN') }),

  logout: () =>
    set({ accessToken: null, refreshToken: null, username: null, roles: [], isAdmin: false }),
}))
