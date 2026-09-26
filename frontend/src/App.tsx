import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Loading } from './components/ui'
import { useAuth } from './lib/auth'
import { LoginPage } from './pages/Login'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const Explore = lazy(() => import('./explorer/ExplorePage'))
const Topology = lazy(() => import('./topology/TopologyPage'))
const Devices = lazy(() => import('./devices/DevicesPage'))
const DeviceDetail = lazy(() => import('./devices/DeviceDetailPage'))
const Connections = lazy(() => import('./pages/Connections'))
const Locations = lazy(() => import('./locations/LocationsPage'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Events = lazy(() => import('./pages/Events'))
const Reports = lazy(() => import('./pages/Reports'))
const Settings = lazy(() => import('./pages/Settings'))
const Discovery = lazy(() => import('./pages/Discovery'))

export function App() {
  const { user, loading } = useAuth()
  if (loading) return <Loading label="Starting…" />
  if (!user) return <LoginPage />
  return (
    <Layout>
      <Suspense fallback={<Loading />}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/explore" element={<Explore />} />
          <Route path="/topology" element={<Topology />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/devices/printers" element={<Devices preset="printer" />} />
          <Route path="/devices/computers" element={<Devices preset="computer" />} />
          <Route path="/devices/:id" element={<DeviceDetail />} />
          <Route path="/connections" element={<Connections />} />
          <Route path="/locations" element={<Locations />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/events" element={<Events />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/discovery" element={<Discovery />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </Layout>
  )
}
