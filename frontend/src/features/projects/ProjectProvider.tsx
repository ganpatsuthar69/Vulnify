import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { useAuth } from '@/features/auth/AuthProvider'
import {
  createProject as apiCreateProject,
  getEcosystemCapabilities,
  listProjects as apiListProjects,
  ProjectApiError,
} from './projectApi'
import type { CreateProjectInput, EcosystemCapability, Project } from './types'

const STORAGE_ACTIVE_PROJECT_KEY = 'vulnify_active_project_id'

interface ProjectContextValue {
  projects: Project[]
  activeProject: Project | null
  activeProjectId: string | null
  capabilities: EcosystemCapability[]
  capabilitiesLoading: boolean
  isLoading: boolean
  error: string | null
  selectProject: (projectId: string) => void
  createProject: (input: CreateProjectInput) => Promise<Project>
  refreshProjects: () => Promise<void>
  refreshCapabilities: () => Promise<void>
}

const ProjectContext = createContext<ProjectContextValue | undefined>(undefined)

function getStoredProjectId(): string | null {
  try {
    return localStorage.getItem(STORAGE_ACTIVE_PROJECT_KEY)
  } catch {
    return null
  }
}

function setStoredProjectId(id: string | null): void {
  try {
    if (id) {
      localStorage.setItem(STORAGE_ACTIVE_PROJECT_KEY, id)
    } else {
      localStorage.removeItem(STORAGE_ACTIVE_PROJECT_KEY)
    }
  } catch {
    // Gracefully ignore local storage write errors (e.g. storage disabled/full)
  }
}

export function ProjectProvider({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  const [projects, setProjects] = useState<Project[]>([])
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null)
  const [capabilities, setCapabilities] = useState<EcosystemCapability[]>([])
  const [capabilitiesLoading, setCapabilitiesLoading] = useState<boolean>(false)
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  const refreshCapabilities = useCallback(async (): Promise<void> => {
    if (status !== 'authenticated') {
      setCapabilities([])
      return
    }
    setCapabilitiesLoading(true)
    try {
      const res = await getEcosystemCapabilities()
      setCapabilities(res.capabilities)
    } catch {
      // Fail silently or leave existing capabilities intact
    } finally {
      setCapabilitiesLoading(false)
    }
  }, [status])

  const refreshProjects = useCallback(async (): Promise<void> => {
    if (status !== 'authenticated') {
      setProjects([])
      setActiveProjectId(null)
      setStoredProjectId(null)
      setIsLoading(false)
      return
    }

    setIsLoading(true)
    setError(null)

    try {
      const fetchedProjects = await apiListProjects()
      setProjects(fetchedProjects)

      // Resolve active project selection with persistent fallback
      const storedId = getStoredProjectId()
      const matchingStored = storedId ? fetchedProjects.find((p) => p.id === storedId) : null

      if (matchingStored) {
        setActiveProjectId(matchingStored.id)
      } else if (fetchedProjects.length > 0) {
        // Fallback deterministically to first available project
        const fallbackProject = fetchedProjects[0]!
        setActiveProjectId(fallbackProject.id)
        setStoredProjectId(fallbackProject.id)
      } else {
        // Empty project list
        setActiveProjectId(null)
        setStoredProjectId(null)
      }
    } catch (err) {
      if (err instanceof ProjectApiError && err.status === 401) {
        setProjects([])
        setActiveProjectId(null)
      } else {
        setError(err instanceof Error ? err.message : 'Failed to load projects.')
      }
    } finally {
      setIsLoading(false)
    }
  }, [status])

  useEffect(() => {
    void refreshProjects()
    void refreshCapabilities()
  }, [refreshProjects, refreshCapabilities])

  const selectProject = useCallback((projectId: string): void => {
    setActiveProjectId((prev) => {
      if (prev === projectId) return prev
      setStoredProjectId(projectId)
      return projectId
    })
  }, [])

  const createProject = useCallback(
    async (input: CreateProjectInput): Promise<Project> => {
      const newProject = await apiCreateProject(input)
      setProjects((prev) => [newProject, ...prev.filter((p) => p.id !== newProject.id)])
      setActiveProjectId(newProject.id)
      setStoredProjectId(newProject.id)
      return newProject
    },
    [],
  )

  const activeProject = useMemo(() => {
    if (!activeProjectId) return null
    return projects.find((p) => p.id === activeProjectId) ?? null
  }, [projects, activeProjectId])

  const value = useMemo<ProjectContextValue>(
    () => ({
      projects,
      activeProject,
      activeProjectId,
      capabilities,
      capabilitiesLoading,
      isLoading,
      error,
      selectProject,
      createProject,
      refreshProjects,
      refreshCapabilities,
    }),
    [
      projects,
      activeProject,
      activeProjectId,
      capabilities,
      capabilitiesLoading,
      isLoading,
      error,
      selectProject,
      createProject,
      refreshProjects,
      refreshCapabilities,
    ],
  )

  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>
}

export function useProjects(): ProjectContextValue {
  const context = useContext(ProjectContext)
  if (!context) {
    throw new Error('useProjects must be used within a ProjectProvider')
  }
  return context
}
