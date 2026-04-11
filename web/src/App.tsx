import { Suspense, lazy } from 'react'
import { Routes, Route } from 'react-router-dom'
import { Toaster } from 'sonner'
import Layout from './layouts/Layout'
import { ThemeProvider } from './contexts/ThemeContext'
import { SearchProvider } from './contexts/SearchContext'

// Lazy load pages
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Health = lazy(() => import('./pages/Health'))
const CrowdSecHealth = lazy(() => import('./pages/CrowdSecHealth'))
const Allowlist = lazy(() => import('./pages/Allowlist'))
const Scenarios = lazy(() => import('./pages/Scenarios'))
const Logs = lazy(() => import('./pages/Logs'))
const Services = lazy(() => import('./pages/Services'))
const DecisionAnalysis = lazy(() => import('./pages/DecisionAnalysis'))
const AlertAnalysis = lazy(() => import('./pages/AlertAnalysis'))
const Bouncers = lazy(() => import('./pages/Bouncers'))
const Terminal = lazy(() => import('./pages/Terminal'))
const Hub = lazy(() => import('./pages/Hub'))
const HubBrowser = lazy(() => import('./pages/HubBrowser'))
const HubCategory = lazy(() => import('./pages/HubCategory'))
const Metrics = lazy(() => import('./pages/Metrics'))
const History = lazy(() => import('./pages/History'))

function App() {
  return (
    <>
      <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
        <SearchProvider>
          <Layout>
            <Suspense fallback={<div className="flex items-center justify-center h-full w-full">Loading...</div>}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/health" element={<Health />} />
                <Route path="/crowdsec-health" element={<CrowdSecHealth />} />
                <Route path="/allowlist" element={<Allowlist />} />
                <Route path="/scenarios" element={<Scenarios />} />
                <Route path="/decisions" element={<DecisionAnalysis />} />
                <Route path="/alerts" element={<AlertAnalysis />} />
                <Route path="/logs" element={<Logs />} />
                <Route path="/services" element={<Services />} />
                <Route path="/bouncers" element={<Bouncers />} />
                <Route path="/terminal" element={<Terminal />} />
                <Route path="/hub" element={<Hub />} />
                <Route path="/hub/browser" element={<HubBrowser />} />
                <Route path="/hub/:category" element={<HubCategory />} />
                <Route path="/metrics" element={<Metrics />} />
                <Route path="/history" element={<History />} />
              </Routes>
            </Suspense>
          </Layout>
        </SearchProvider>
        <Toaster position="top-right" richColors />
      </ThemeProvider>
    </>
  )
}

export default App
