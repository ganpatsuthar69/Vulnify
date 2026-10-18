import { BrowserRouter, Navigate, Route, Routes } from 'react-router'
import { AuthProvider } from '@/features/auth/AuthProvider'
import { LoginPage } from '@/features/auth/LoginPage'
import { ProtectedRoute } from '@/features/auth/ProtectedRoute'
import { RegisterPage } from '@/features/auth/RegisterPage'
import { ProjectProvider } from '@/features/projects/ProjectProvider'
import { AppLayout } from '@/shared/components/AppLayout'

// Feature Pages
import { DashboardPage } from '@/features/dashboard/DashboardPage'
import { DependenciesPage } from '@/features/dependencies/DependenciesPage'
import { ImportDataPage } from '@/features/import/ImportDataPage'
import { IngestionHistoryPage } from '@/features/import/IngestionHistoryPage'
import { FindingsPage } from '@/features/findings/FindingsPage'
import { FindingDetailPage } from '@/features/findings/FindingDetailPage'
import { DependencyGraphPage } from '@/features/graph/DependencyGraphPage'
import { ExposurePathsPage } from '@/features/exposure/ExposurePathsPage'
import { RiskPrioritiesPage } from '@/features/priorities/RiskPrioritiesPage'
import { ReviewQueuePage } from '@/features/review/ReviewQueuePage'
import { UpgradeCandidatesPage } from '@/features/remediation/UpgradeCandidatesPage'
import { FixSimulationPage } from '@/features/remediation/FixSimulationPage'
import { GitHubIssuesPage } from '@/features/remediation/GitHubIssuesPage'
import { AiInvestigationPage } from '@/features/intelligence/AiInvestigationPage'
import { InvestigationHistoryPage } from '@/features/intelligence/InvestigationHistoryPage'
import { BenchmarksPage } from '@/features/intelligence/BenchmarksPage'
import { ProjectSettingsPage } from '@/features/projects/ProjectSettingsPage'
import { IntegrationsPage } from '@/features/administration/IntegrationsPage'

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ProjectProvider>
          <Routes>
            {/* Unauthenticated Auth Routes */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Authenticated Application Shell */}
            <Route element={<ProtectedRoute />}>
              <Route element={<AppLayout />}>
                {/* Overview */}
                <Route path="/" element={<DashboardPage />} />

                {/* Inventory */}
                <Route path="/dependencies" element={<DependenciesPage />} />
                <Route path="/import" element={<ImportDataPage />} />
                <Route path="/history" element={<IngestionHistoryPage />} />

                {/* Security Analysis */}
                <Route path="/findings" element={<FindingsPage />} />
                <Route path="/findings/:id" element={<FindingDetailPage />} />
                <Route path="/graph" element={<DependencyGraphPage />} />
                <Route path="/exposure-paths" element={<ExposurePathsPage />} />

                {/* Prioritization */}
                <Route path="/priorities" element={<RiskPrioritiesPage />} />
                <Route path="/review-queue" element={<ReviewQueuePage />} />

                {/* Remediation */}
                <Route path="/upgrades" element={<UpgradeCandidatesPage />} />
                <Route path="/simulation" element={<FixSimulationPage />} />
                <Route path="/github-issues" element={<GitHubIssuesPage />} />

                {/* Intelligence */}
                <Route path="/investigation" element={<AiInvestigationPage />} />
                <Route path="/investigation-history" element={<InvestigationHistoryPage />} />
                <Route path="/benchmarks" element={<BenchmarksPage />} />

                {/* Administration */}
                <Route path="/projects" element={<Navigate to="/project-settings" replace />} />
                <Route path="/project-settings" element={<ProjectSettingsPage />} />
                <Route path="/integrations" element={<IntegrationsPage />} />
              </Route>
            </Route>

            {/* Catch-all Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </ProjectProvider>
      </AuthProvider>
    </BrowserRouter>
  )
}
