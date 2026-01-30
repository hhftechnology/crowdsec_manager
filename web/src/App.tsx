import { Suspense, lazy } from 'react'
import { Routes, Route } from 'react-router-dom'
import { Toaster } from 'sonner'
import { ResponsiveLayout } from './components/layout/ResponsiveLayout'
import { SafeThemeProvider } from './components/common/SafeThemeProvider'
import { ProxyProvider } from './contexts/ProxyContext'
import { DeploymentProvider } from './contexts/DeploymentContext'
import { ErrorProvider } from './contexts/ErrorContext'
import { LoadingProvider } from './contexts/LoadingContext'
import { AccessibilityProvider } from './components/accessibility/AccessibilityProvider'
import { SkipLinks } from './components/accessibility/SkipLinks'
import { ErrorBoundary } from './components/common/ErrorBoundary'
import { SafeNavigation } from './components/common/SafeNavigation'
import { SuspenseFallback } from './components/common/LoadingStates'

import { FeatureGuard } from './components/common/FeatureGuard'

// Lazy load pages
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Health = lazy(() => import('./pages/Health'))
const CrowdSecHealth = lazy(() => import('./pages/CrowdSecHealth'))
const IPManagement = lazy(() => import('./pages/IPManagement'))
const Whitelist = lazy(() => import('./pages/Whitelist'))
const Allowlist = lazy(() => import('./pages/Allowlist'))
const Scenarios = lazy(() => import('./pages/Scenarios'))
const Captcha = lazy(() => import('./pages/Captcha'))
const Logs = lazy(() => import('./pages/Logs'))
const Backup = lazy(() => import('./pages/Backup'))
const Update = lazy(() => import('./pages/Update'))
const Cron = lazy(() => import('./pages/Cron'))
const Services = lazy(() => import('./pages/Services'))
const Configuration = lazy(() => import('./pages/Configuration'))
const DecisionAnalysis = lazy(() => import('./pages/DecisionAnalysis'))
const AlertAnalysis = lazy(() => import('./pages/AlertAnalysis'))
const Notifications = lazy(() => import('./pages/Notifications'))
const Profiles = lazy(() => import('./pages/Profiles'))
const Bouncers = lazy(() => import('./pages/Bouncers'))
const Addons = lazy(() => import('./pages/Addons'))

function App() {
  return (
    <>
      <SafeThemeProvider defaultTheme="dark">
        <ErrorProvider>
          <LoadingProvider>
            <ErrorBoundary>
              <AccessibilityProvider>
                <ErrorBoundary>
                  <ProxyProvider>
                    <DeploymentProvider>
                      <SafeNavigation>
                      {/* Skip links for keyboard navigation */}
                      <SkipLinks />
                      
                      <ResponsiveLayout>
                        <Suspense fallback={<SuspenseFallback message="Loading page content..." />}>
                          <main id="main-content" role="main" tabIndex={-1}>
                            <Routes>
                              <Route path="/" element={<Dashboard />} />
                              <Route path="/health" element={<Health />} />
                              <Route path="/crowdsec-health" element={<CrowdSecHealth />} />
                              <Route path="/ip-management" element={<IPManagement />} />
                              <Route path="/whitelist" element={
                                <FeatureGuard feature="whitelistProxy">
                                  <Whitelist />
                                </FeatureGuard>
                              } />
                              <Route path="/allowlist" element={<Allowlist />} />
                              <Route path="/scenarios" element={<Scenarios />} />
                              <Route path="/captcha" element={
                                <FeatureGuard feature="captcha">
                                  <Captcha />
                                </FeatureGuard>
                              } />
                              <Route path="/decisions" element={<DecisionAnalysis />} />
                              <Route path="/alerts" element={<AlertAnalysis />} />
                              <Route path="/logs" element={
                                <FeatureGuard feature="logs">
                                  <Logs />
                                </FeatureGuard>
                              } />
                              <Route path="/backup" element={
                                <FeatureGuard feature="backup">
                                  <Backup />
                                </FeatureGuard>
                              } />
                              <Route path="/update" element={<Update />} />
                              <Route path="/cron" element={
                                <FeatureGuard feature="cronJobs">
                                  <Cron />
                                </FeatureGuard>
                              } />
                              <Route path="/services" element={<Services />} />
                              <Route path="/configuration" element={<Configuration />} />
                              <Route path="/notifications" element={<Notifications />} />
                              <Route path="/profiles" element={<Profiles />} />
                              <Route path="/bouncers" element={<Bouncers />} />
                              <Route path="/addons" element={<Addons />} />
                            </Routes>
                          </main>
                        </Suspense>
                      </ResponsiveLayout>
                      <Toaster position="top-right" richColors />
                    </SafeNavigation>
                    </DeploymentProvider>
                  </ProxyProvider>
                </ErrorBoundary>
              </AccessibilityProvider>
            </ErrorBoundary>
          </LoadingProvider>
        </ErrorProvider>
      </SafeThemeProvider>
    </>
  )
}

export default App
