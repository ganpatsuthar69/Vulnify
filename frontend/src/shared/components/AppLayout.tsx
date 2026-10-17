import {
  ArrowUpCircle,
  BarChart3,
  Bot,
  CheckSquare,
  ChevronLeft,
  ChevronRight,
  Clock,
  FlaskConical,
  FolderGit2,
  GitPullRequest,
  History,
  LayoutDashboard,
  Link2,
  LogOut,
  Menu,
  Network,
  Package,
  Route,
  Settings,
  ShieldAlert,
  Sliders,
  UploadCloud,
  X,
  type LucideIcon,
} from 'lucide-react'
import { useState, useEffect } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router'
import { useAuth } from '@/features/auth/AuthProvider'
import { CreateProjectModal } from '@/features/projects/CreateProjectModal'
import { ProjectSelector } from '@/features/projects/ProjectSelector'
import { useProjects } from '@/features/projects/ProjectProvider'
import vulnifyLogo from '@/assets/vulnify-logo.png'

interface NavItem {
  name: string
  path: string
  icon: LucideIcon
  badge?: string
  isPlanned?: boolean
}

interface NavGroup {
  group: string
  items: NavItem[]
}

const NAV_GROUPS: NavGroup[] = [
  {
    group: 'Overview',
    items: [
      { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    ],
  },
  {
    group: 'Inventory',
    items: [
      { name: 'Dependencies', path: '/dependencies', icon: Package },
      { name: 'Import Data', path: '/import', icon: UploadCloud },
      { name: 'Ingestion History', path: '/history', icon: History },
    ],
  },
  {
    group: 'Security Analysis',
    items: [
      { name: 'Findings', path: '/findings', icon: ShieldAlert },
      { name: 'Dependency Graph', path: '/graph', icon: Network },
      { name: 'Exposure Paths', path: '/exposure-paths', icon: Route },
    ],
  },
  {
    group: 'Prioritization',
    items: [
      { name: 'Risk Priorities', path: '/priorities', icon: Sliders },
      { name: 'Review Queue', path: '/review-queue', icon: CheckSquare },
    ],
  },
  {
    group: 'Remediation',
    items: [
      { name: 'Upgrade Candidates', path: '/upgrades', icon: ArrowUpCircle },
      { name: 'Fix Simulation', path: '/simulation', icon: FlaskConical, badge: 'US-502', isPlanned: true },
      { name: 'GitHub Issues', path: '/github-issues', icon: GitPullRequest },
    ],
  },
  {
    group: 'Intelligence',
    items: [
      { name: 'AI Investigation', path: '/investigation', icon: Bot },
      { name: 'Investigation History', path: '/investigation-history', icon: Clock, badge: 'US-603', isPlanned: true },
      { name: 'Benchmarks', path: '/benchmarks', icon: BarChart3 },
    ],
  },
  {
    group: 'Administration',
    items: [
      { name: 'Projects', path: '/projects', icon: FolderGit2 },
      { name: 'Project Settings', path: '/project-settings', icon: Settings },
      { name: 'Integrations', path: '/integrations', icon: Link2 },
    ],
  },
]

export function AppLayout() {
  const { user, logout } = useAuth()
  const { activeProject } = useProjects()
  const location = useLocation()

  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)

  // Close mobile menu on route change
  useEffect(() => {
    setIsMobileMenuOpen(false)
  }, [location.pathname])

  // Handle escape key to close mobile drawer
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && isMobileMenuOpen) {
        setIsMobileMenuOpen(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isMobileMenuOpen])

  // Compute current page title
  const currentNavItem = NAV_GROUPS.flatMap((g) => g.items).find((item) =>
    item.path === '/'
      ? location.pathname === '/'
      : location.pathname.startsWith(item.path),
  )
  const pageTitle = currentNavItem ? currentNavItem.name : 'Security Workspace'

  const isAdmin = user?.role === 'admin'

  return (
    <div className="flex h-screen overflow-hidden bg-[#0b121a] text-slate-200">
      {/* Mobile Drawer Backdrop */}
      {isMobileMenuOpen && (
        <div
          role="presentation"
          onClick={() => setIsMobileMenuOpen(false)}
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden transition-opacity"
        />
      )}

      {/* Persistent Sidebar */}
      <aside
        aria-label="Workspace Navigation"
        className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-slate-800 bg-[#0f1822] transition-all duration-200 lg:static ${
          isMobileMenuOpen ? 'translate-x-0 w-64' : '-translate-x-full lg:translate-x-0'
        } ${isSidebarCollapsed ? 'lg:w-20' : 'lg:w-64'}`}
      >
        {/* Brand & Logo Header */}
        <div className="flex h-16 items-center justify-between border-b border-slate-800/80 px-4">
          <NavLink
            to="/"
            className="flex items-center gap-3 overflow-hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 rounded-lg p-1"
          >
            <img
              src={vulnifyLogo}
              alt="Vulnify"
              className="h-8 w-auto flex-shrink-0 object-contain"
            />
            {!isSidebarCollapsed && (
              <div className="flex flex-col">
                <span className="text-base font-bold tracking-tight text-white leading-none">
                  Vulnify
                </span>
                <span className="text-[10px] font-semibold text-sky-400 tracking-wider uppercase mt-1">
                  Connected Security
                </span>
              </div>
            )}
          </NavLink>

          {/* Mobile close button */}
          <button
            type="button"
            onClick={() => setIsMobileMenuOpen(false)}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white lg:hidden"
            aria-label="Close navigation menu"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Sidebar Navigation Items */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6 scrollbar-thin scrollbar-thumb-slate-800">
          {NAV_GROUPS.map((group) => (
            <div key={group.group} className="space-y-1">
              {!isSidebarCollapsed && (
                <div className="px-3 text-[10px] font-bold tracking-wider text-slate-300 uppercase mb-1">
                  {group.group}
                </div>
              )}
              {group.items.map((item) => {
                const Icon = item.icon
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === '/'}
                    title={isSidebarCollapsed ? item.name : undefined}
                    className={({ isActive }) =>
                      `group flex items-center justify-between rounded-lg px-3 py-2 text-xs font-medium transition-all ${
                        isActive
                          ? 'bg-sky-500/15 text-sky-300 font-semibold ring-1 ring-sky-500/30'
                          : 'text-slate-400 hover:bg-slate-800/70 hover:text-slate-200'
                      } ${isSidebarCollapsed ? 'justify-center px-2' : ''}`
                    }
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <Icon
                        className="h-4 w-4 flex-shrink-0 text-slate-400 group-hover:text-sky-300 transition-colors"
                        aria-hidden="true"
                      />
                      {!isSidebarCollapsed && (
                        <span className="truncate">{item.name}</span>
                      )}
                    </div>

                    {!isSidebarCollapsed && item.badge && (
                      <span
                        className={`rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider ${
                          item.isPlanned
                            ? 'bg-amber-500/15 border border-amber-500/30 text-amber-300'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </NavLink>
                )
              })}
            </div>
          ))}
        </nav>

        {/* Sidebar Collapse Toggle Button (Desktop only) */}
        <div className="hidden border-t border-slate-800/80 p-3 lg:block">
          <button
            type="button"
            onClick={() => setIsSidebarCollapsed((prev) => !prev)}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 py-1.5 text-xs font-medium text-slate-400 transition-colors hover:border-slate-700 hover:bg-slate-800 hover:text-slate-200"
            aria-label={isSidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {isSidebarCollapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <>
                <ChevronLeft className="h-4 w-4" />
                <span>Collapse sidebar</span>
              </>
            )}
          </button>
        </div>
      </aside>

      {/* Main Layout Area */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Top Header Bar */}
        <header className="flex h-16 flex-shrink-0 items-center justify-between border-b border-slate-800 bg-[#0f1822]/90 px-4 sm:px-6 backdrop-blur">
          {/* Left: Mobile hamburger + Active Project Selector */}
          <div className="flex items-center gap-4">
            <button
              type="button"
              onClick={() => setIsMobileMenuOpen(true)}
              className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white lg:hidden"
              aria-label="Open navigation menu"
            >
              <Menu className="h-5 w-5" />
            </button>

            {/* Top Bar Project Selector */}
            <div className="flex items-center gap-3">
              <ProjectSelector onOpenCreateModal={() => setIsCreateModalOpen(true)} />

              {activeProject && (
                <div className="hidden sm:flex items-center gap-2 text-xs">
                  <span className="rounded bg-sky-500/10 border border-sky-500/30 px-2 py-0.5 font-bold text-sky-300 uppercase text-[10px]">
                    {activeProject.ecosystem}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Right: User menu & Sign Out */}
          <div className="flex items-center gap-3 sm:gap-4">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-800 text-xs font-bold text-sky-400 ring-1 ring-slate-700">
                {(user?.name ?? 'U').charAt(0).toUpperCase()}
              </div>
              <div className="hidden sm:flex flex-col">
                <span className="text-xs font-semibold text-slate-200 leading-none">
                  {user?.name ?? 'User'}
                </span>
                <span className="text-[10px] font-medium text-slate-300 mt-0.5">
                  {user?.email}
                </span>
              </div>
              <span
                className={`hidden md:inline-flex items-center rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                  isAdmin
                    ? 'border border-sky-400/30 bg-sky-500/10 text-sky-300'
                    : 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                }`}
              >
                {user?.role ?? 'user'}
              </span>
            </div>

            <div className="h-5 w-[1px] bg-slate-800" aria-hidden="true" />

            <button
              type="button"
              onClick={() => void logout()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-xs font-semibold text-slate-300 transition-colors hover:border-slate-600 hover:bg-slate-700 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
              title="Sign out of Vulnify"
            >
              <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">Sign out</span>
            </button>
          </div>
        </header>

        {/* Breadcrumb / Title Bar */}
        <div className="flex items-center justify-between border-b border-slate-800/60 bg-[#0b121a]/60 px-6 py-2 text-xs">
          <div className="flex items-center gap-2 text-slate-300">
            <NavLink to="/" className="text-slate-300 hover:text-slate-100 transition-colors">
              Vulnify
            </NavLink>
            <span className="text-slate-400">/</span>
            <span className="font-semibold text-slate-100">{pageTitle}</span>
          </div>

          {activeProject ? (
            <div className="flex items-center gap-1.5 text-slate-300 text-[11px]">
              <span className="text-slate-400">Project:</span>
              <span className="font-medium text-slate-200">{activeProject.name}</span>
            </div>
          ) : (
            <span className="text-amber-400 text-[11px]">No active project selected</span>
          )}
        </div>

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto p-6 scrollbar-thin scrollbar-thumb-slate-800">
          <div className="mx-auto max-w-7xl">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Global Project Creation Modal */}
      <CreateProjectModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
      />
    </div>
  )
}
