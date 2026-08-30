import { NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Users, Shield, ScrollText, KeyRound, LogOut, HeartPulse } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { authApi } from '@/api/auth'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const nav = [
  { to: '/dashboard',      label: 'Dashboard',      Icon: LayoutDashboard },
  { to: '/users',          label: 'Users',           Icon: Users },
  { to: '/roles',          label: 'Roles',           Icon: Shield },
  { to: '/audit',          label: 'Audit Log',       Icon: ScrollText },
  { to: '/login-attempts', label: 'Login Attempts',  Icon: KeyRound },
  { to: '/system-health',  label: 'System Health',   Icon: HeartPulse },
]

export default function Sidebar() {
  const { username, accessToken, logout } = useAuthStore()
  const navigate = useNavigate()

  async function handleLogout() {
    try {
      if (accessToken) await authApi.logout(accessToken)
    } catch { /* ignore — blacklist best-effort */ }
    logout()
    navigate('/login')
    toast.success('Logged out successfully')
  }

  return (
    <aside className="w-56 bg-white border-r border-gray-200 flex flex-col flex-shrink-0">
      {/* Brand */}
      <div className="px-5 py-4 border-b border-gray-100">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-md bg-blue-600 flex items-center justify-center">
            <Shield size={14} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-bold text-gray-900 leading-none">JWT Auth</p>
            <p className="text-[10px] text-gray-400 mt-0.5">Admin Panel</p>
          </div>
        </div>
      </div>

      {/* Nav links */}
      <nav className="flex-1 px-3 py-3 space-y-0.5">
        {nav.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                isActive
                  ? 'bg-blue-50 text-blue-700'
                  : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900',
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User + logout */}
      <div className="px-3 py-3 border-t border-gray-100">
        <div className="px-3 py-2 mb-1">
          <p className="text-xs text-gray-400">Logged in as</p>
          <p className="text-sm font-medium text-gray-800 truncate">{username}</p>
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-md text-sm text-red-600 hover:bg-red-50 transition-colors"
        >
          <LogOut size={15} />
          Sign out
        </button>
      </div>
    </aside>
  )
}
