// ─── Auth ─────────────────────────────────────────────────────────────────────

export interface AuthRequest {
  username: string
  password: string
}

export interface AuthResponse {
  accessToken: string
  refreshToken: string
  tokenType: string
  expiresIn: number
  username: string
  roles: string[]
}

// ─── User ─────────────────────────────────────────────────────────────────────

export interface UserSummary {
  id: number
  username: string
  email: string | null
  firstName: string | null
  lastName: string | null
  createdAt: string
  updatedAt: string
  emailVerified: boolean
  enabled: boolean
  accountNonLocked: boolean
  lockedAt: string | null
  roles: string[]
  deletionRequestedAt: string | null
  deletedAt: string | null
}

export interface AdminRegisterRequest {
  username: string
  password: string
  roles: string[]
}

export interface UserSearchParams {
  username?: string
  email?: string
  role?: string
  enabled?: boolean | null
  accountNonLocked?: boolean | null
  page?: number
  size?: number
}

// ─── Roles ────────────────────────────────────────────────────────────────────

export interface RoleResponse {
  id: number
  name: string
  description: string | null
}

export interface RoleRequest {
  name: string
  description?: string
}

export interface AssignRoleRequest {
  roleName: string
}

// ─── Audit ────────────────────────────────────────────────────────────────────

export interface AuditEventSummary {
  id: number
  username: string
  eventType: string
  ipAddress: string | null
  details: string | null
  createdAt: string
}

// ─── Login Attempts ──────────────────────────────────────────────────────────

export interface LoginAttemptSummary {
  id: number
  username: string
  ipAddress: string | null
  success: boolean
  attemptedAt: string
}

// ─── Pagination ───────────────────────────────────────────────────────────────

export interface PagedResponse<T> {
  content: T[]
  page: number
  size: number
  totalElements: number
  totalPages: number
  last: boolean
}

// ─── API error ────────────────────────────────────────────────────────────────

export interface ApiError {
  timestamp: string
  status: number
  error: string
  message: string
}
