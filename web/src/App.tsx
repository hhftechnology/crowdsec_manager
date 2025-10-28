import { Routes, Route } from 'react-router-dom'
import { Toaster } from 'sonner'
import Layout from './components/Layout'

// Pages
import Dashboard from './pages/Dashboard'
import Health from './pages/Health'
import IPManagement from './pages/IPManagement'
import Whitelist from './pages/Whitelist'
import Scenarios from './pages/Scenarios'
import Captcha from './pages/Captcha'
import Logs from './pages/Logs'
import Backup from './pages/Backup'
import Update from './pages/Update'
import Cron from './pages/Cron'
import Services from './pages/Services'

function App() {
  return (
    <>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/health" element={<Health />} />
          <Route path="/ip-management" element={<IPManagement />} />
          <Route path="/whitelist" element={<Whitelist />} />
          <Route path="/scenarios" element={<Scenarios />} />
          <Route path="/captcha" element={<Captcha />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/backup" element={<Backup />} />
          <Route path="/update" element={<Update />} />
          <Route path="/cron" element={<Cron />} />
          <Route path="/services" element={<Services />} />
        </Routes>
      </Layout>
      <Toaster position="top-right" richColors />
    </>
  )
}

export default App
