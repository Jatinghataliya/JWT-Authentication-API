import api from './axios'
import type { AuditEventSummary, PagedResponse } from '@/types'

export const auditApi = {
  getPaged: (username?: string, page = 0, size = 20) => {
    const params = new URLSearchParams({ page: String(page), size: String(size) })
    if (username) params.set('username', username)
    return api
      .get<PagedResponse<AuditEventSummary>>(`/admin/audit/paged?${params}`)
      .then((r) => r.data)
  },
}
