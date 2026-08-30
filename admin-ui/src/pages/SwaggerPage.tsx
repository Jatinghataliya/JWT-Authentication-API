import { ExternalLink, BookOpen, Code, FileJson } from 'lucide-react'

const SWAGGER_URL = 'http://localhost:8080/swagger-ui/index.html'
const OPENAPI_URL = 'http://localhost:8080/api-docs'

const endpoints = [
  { tag: '1. Authentication', color: 'bg-blue-50 border-blue-200 text-blue-700', methods: ['POST /api/auth/register', 'POST /api/auth/login', 'POST /api/auth/refresh', 'POST /api/auth/logout', 'GET /api/auth/verify', 'POST /api/auth/resend-verification', 'POST /api/auth/forgot-password', 'POST /api/auth/reset-password'] },
  { tag: '2. User', color: 'bg-green-50 border-green-200 text-green-700', methods: ['GET /api/user/me', 'PUT /api/user/me', 'PUT /api/user/me/password', 'DELETE /api/user/me', 'GET /api/user/dashboard'] },
  { tag: '3. Moderator', color: 'bg-yellow-50 border-yellow-200 text-yellow-700', methods: ['GET /api/moderator/dashboard'] },
  { tag: '4. Admin — Users', color: 'bg-purple-50 border-purple-200 text-purple-700', methods: ['GET /api/admin/users', 'GET /api/admin/users/paged', 'GET /api/admin/users/search', 'GET /api/admin/users/export.csv', 'POST /api/admin/users', 'GET /api/admin/users/{id}', 'DELETE /api/admin/users/{id}', 'DELETE /api/admin/users/{id}/erase', 'PATCH /api/admin/users/{id}/enable', 'PATCH /api/admin/users/{id}/disable', 'PATCH /api/admin/users/{id}/lock', 'PATCH /api/admin/users/{id}/unlock', 'POST /api/admin/users/{id}/roles', 'DELETE /api/admin/users/{id}/roles', 'GET /api/admin/users/{id}/login-attempts'] },
  { tag: '4. Admin — Roles', color: 'bg-indigo-50 border-indigo-200 text-indigo-700', methods: ['GET /api/admin/roles', 'POST /api/admin/roles', 'GET /api/admin/roles/{id}', 'PUT /api/admin/roles/{id}', 'DELETE /api/admin/roles/{id}'] },
  { tag: '4. Admin — Audit & Settings', color: 'bg-red-50 border-red-200 text-red-700', methods: ['GET /api/admin/audit', 'GET /api/admin/audit/paged', 'GET /api/admin/settings/password-policy', 'PUT /api/admin/settings/password-policy'] },
]

const methodColor: Record<string, string> = {
  GET:    'bg-blue-100 text-blue-700',
  POST:   'bg-green-100 text-green-700',
  PUT:    'bg-yellow-100 text-yellow-700',
  PATCH:  'bg-orange-100 text-orange-700',
  DELETE: 'bg-red-100 text-red-700',
}

export default function SwaggerPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BookOpen size={18} className="text-blue-600" />
          <div>
            <h1 className="text-xl font-bold text-gray-900">API Documentation</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Spring Boot 3.2 · JWT Auth API · OpenAPI 3.0
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <a href={OPENAPI_URL} target="_blank" rel="noopener noreferrer"
            className="btn-secondary btn-sm flex items-center gap-1.5">
            <FileJson size={13} /> OpenAPI JSON
          </a>
          <a href={SWAGGER_URL} target="_blank" rel="noopener noreferrer"
            className="btn-primary btn-sm flex items-center gap-1.5">
            <ExternalLink size={13} /> Open Swagger UI
          </a>
        </div>
      </div>

      {/* Notice */}
      <div className="card p-4 flex items-start gap-3 bg-blue-50 border-blue-200">
        <Code size={16} className="text-blue-500 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-blue-800">Swagger UI opens in a new tab</p>
          <p className="text-xs text-blue-600 mt-0.5">
            Browsers block embedding localhost pages inside iframes.
            Click <strong>Open Swagger UI</strong> above to use the interactive docs.
            Once open, click <strong>Authorize</strong> and paste your access token to try authenticated endpoints.
          </p>
        </div>
      </div>

      {/* Endpoint groups */}
      <div className="space-y-4">
        {endpoints.map((group) => (
          <div key={group.tag} className="card">
            <div className="px-5 py-3 border-b border-gray-100 flex items-center gap-2">
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${group.color}`}>
                {group.tag}
              </span>
            </div>
            <div className="p-4 flex flex-wrap gap-2">
              {group.methods.map((m) => {
                const [method, ...pathParts] = m.split(' ')
                const path = pathParts.join(' ')
                return (
                  <span key={m} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-gray-100 bg-gray-50 text-xs font-mono">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${methodColor[method] ?? 'bg-gray-100 text-gray-600'}`}>
                      {method}
                    </span>
                    <span className="text-gray-700">{path}</span>
                  </span>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
