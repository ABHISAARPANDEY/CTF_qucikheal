import { Suspense, lazy, useState } from 'react';
import { Routes, Route, Outlet, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import CommandPalette from './components/CommandPalette';
import AttackPanel from './components/scenarios/AttackPanel';
import OverviewPage from './components/overview/OverviewPage';

const SystemsMonitorPage = lazy(() => import('./components/systems/SystemsMonitorPage'));
const InfrastructureView = lazy(() => import('./components/infrastructure/InfrastructureView'));
const HoneypotPage = lazy(() => import('./components/honeypot/HoneypotPage'));
const ReportsPage = lazy(() => import('./components/reports/ReportsPage'));
const SettingsPage = lazy(() => import('./components/settings/SettingsPage'));
const AlertsPage = lazy(() => import('./components/alerts/AlertsPage'));








export default function App() {
  return (
    <div className="relative h-screen w-screen flex bg-bg-base text-fg-primary overflow-hidden">
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="alerts" element={<LazyRoute><AlertsPage /></LazyRoute>} />
          <Route path="scenarios" element={<AttackPanel />} />
          <Route path="systems" element={<LazyRoute><SystemsMonitorPage /></LazyRoute>} />
          <Route path="infrastructure" element={<LazyRoute><InfrastructureView /></LazyRoute>} />
          <Route path="honeypot" element={<LazyRoute><HoneypotPage /></LazyRoute>} />
          <Route path="reports" element={<LazyRoute><ReportsPage /></LazyRoute>} />
          <Route path="settings" element={<LazyRoute><SettingsPage /></LazyRoute>} />
        </Route>
      </Routes>
    </div>);

}

function LazyRoute({ children }) {
  return (
    <Suspense fallback={<RouteLoadingFallback />}>
      {children}
    </Suspense>
  );
}

function RouteLoadingFallback() {
  return (
    <div className="flex-1 min-h-0 flex items-center justify-center p-6">
      <div className="rounded-md border border-line bg-bg-1 px-3 py-1.5 text-[12px] text-fg-2">Loading…</div>
    </div>
  );
}

function AppShell() {
  const [mode, setMode] = useState('autonomous');
  const location = useLocation();

  return (
    <>
      <CommandPalette />
      <Sidebar />
      <main className="relative z-10 flex-1 flex flex-col min-w-0 min-h-0">
        <Topbar mode={mode} onModeChange={setMode} />
        <motion.div
          key={location.pathname}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.2 }}
          className="flex-1 min-h-0 flex flex-col">
          
          <Outlet />
        </motion.div>
      </main>
    </>);

}
