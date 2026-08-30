import { useState } from 'react'
import { ExternalLink, RefreshCw, BookOpen } from 'lucide-react'

const SWAGGER_URL = '/swagger-ui/index.html'
const OPENAPI_URL = '/api-docs'

export default function SwaggerPage() {
  const [key, setKey] = useState(0) // increment to force iframe reload

  return (
    <div className="flex flex-col gap-4 h-full">
      {/* Header bar */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2">
          <BookOpen size={18} className="text-blue-600" />
          <div>
            <h1 className="text-xl font-bold text-gray-900">API Documentation</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Live Swagger UI — powered by SpringDoc OpenAPI 3
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* OpenAPI JSON link */}
          <a
            href={OPENAPI_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary btn-sm flex items-center gap-1.5"
          >
            <ExternalLink size={13} />
            OpenAPI JSON
          </a>

          {/* Reload iframe */}
          <button
            className="btn-secondary btn-sm flex items-center gap-1.5"
            onClick={() => setKey((k) => k + 1)}
          >
            <RefreshCw size={13} />
            Reload
          </button>

          {/* Open in new tab */}
          <a
            href={SWAGGER_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-primary btn-sm flex items-center gap-1.5"
          >
            <ExternalLink size={13} />
            Open in new tab
          </a>
        </div>
      </div>

      {/* Info pills */}
      <div className="flex items-center gap-3 flex-shrink-0">
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-green-50 border border-green-200 text-green-700">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block" />
          Spring Boot 3.2 · JWT Auth API
        </span>
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-blue-50 border border-blue-200 text-blue-700">
          OpenAPI 3.0
        </span>
        <span className="text-xs text-gray-400">
          Tip: click <strong>Authorize</strong> in Swagger and paste your access token to try authenticated endpoints
        </span>
      </div>

      {/* Swagger iframe — fills remaining height */}
      <div className="flex-1 rounded-xl border border-gray-200 overflow-hidden shadow-sm min-h-0">
        <iframe
          key={key}
          src={SWAGGER_URL}
          title="Swagger UI"
          className="w-full h-full"
          style={{ minHeight: '700px', border: 'none' }}
          allow="clipboard-write"
        />
      </div>
    </div>
  )
}
