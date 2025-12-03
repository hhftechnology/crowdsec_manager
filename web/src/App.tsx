import { Suspense, lazy } from 'react'
import { Routes, Route } from 'react-router-dom'
import { Toaster } from 'sonner'
import Layout from './components/Layout'
import { ThemeProvider } from './components/ThemeProvider'

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

function App() {
  return (
    <>
      <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
        <Layout>
          <Suspense fallback={<div className="flex items-center justify-center h-full w-full">Loading...</div>}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/health" element={<Health />} />
              <Route path="/crowdsec-health" element={<CrowdSecHealth />} />
              <Route path="/ip-management" element={<IPManagement />} />
              <Route path="/whitelist" element={<Whitelist />} />
              <Route path="/allowlist" element={<Allowlist />} />
              <Route path="/scenarios" element={<Scenarios />} />
              <Route path="/captcha" element={<Captcha />} />
              <Route path="/decisions" element={<DecisionAnalysis />} />
              <Route path="/alerts" element={<AlertAnalysis />} />
              <Route path="/logs" element={<Logs />} />
              <Route path="/backup" element={<Backup />} />
              <Route path="/update" element={<Update />} />
              <Route path="/cron" element={<Cron />} />
              <Route path="/services" element={<Services />} />
              <Route path="/configuration" element={<Configuration />} />
              <Route path="/notifications" element={<Notifications />} />
              <Route path="/profiles" element={<Profiles />} />
              <Route path="/bouncers" element={<Bouncers />} />
            </Routes>
          </Suspense>
        </Layout>
        <Toaster position="top-right" richColors />
      </ThemeProvider>
    </>
  )
}

export default App
