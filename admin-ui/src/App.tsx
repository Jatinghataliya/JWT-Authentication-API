import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'
import LoginPage from '@/pages/LoginPage'
import Layout from '@/components/Layout'
import DashboardPage from '@/pages/DashboardPage'
import UsersPage from '@/pages/UsersPage'
import RolesPage from '@/pages/RolesPage'
import AuditPage from '@/pages/AuditPage'
import LoginAttemptsPage from '@/pages/LoginAttemptsPage'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { accessToken, isAdmin } = useAuthStore()
  if (!accessToken) return <Navigate to="/login" replace />
  if (!isAdmin) return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="card p-8 text-center max-w-sm">
        <div className="text-4xl mb-4">🚫</div>
        <h2 className="text-lg font-semibold text-gray-900 mb-2">Access Denied</h2>
        <p className="text-sm text-gray-500">This panel requires the ADMIN role.</p>
      </div>
    </div>
  )
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <PrivateRoute>
              <Layout />
            </PrivateRoute>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="users" element={<UsersPage />} />
          <Route path="roles" element={<RolesPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="login-attempts" element={<LoginAttemptsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
