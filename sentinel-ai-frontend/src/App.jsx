import { Suspense, lazy, useState } from 'react';
import { Routes, Route, Outlet, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import AmbientBackground from './components/AmbientBackground';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import ComingSoon from './components/ComingSoon';
import AttackPanel from './components/scenarios/AttackPanel';
import ThreatFeedPanel from './components/panels/ThreatFeedPanel';
import RiskMeterPanel from './components/panels/RiskMeterPanel';
import AttackControlPanel from './components/panels/AttackControlPanel';
import AttackTimelinePanel from './components/panels/AttackTimelinePanel';
import AICopilotPanel from './components/panels/AICopilotPanel';
import SystemsOverviewPanel from './components/systems/SystemsOverviewPanel';

const SystemsMonitorPage = lazy(() => import('./components/systems/SystemsMonitorPage'));
const InfrastructureView = lazy(() => import('./components/infrastructure/InfrastructureView'));
const HoneypotPage = lazy(() => import('./components/honeypot/HoneypotPage'));
const ReportsPage = lazy(() => import('./components/reports/ReportsPage'));








export default function App() {
  return (
    <div className="relative h-screen w-screen flex bg-bg-base text-fg-primary overflow-hidden">
      <AmbientBackground />
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardView />} />
          <Route path="scenarios" element={<AttackPanel />} />
          <Route path="systems" element={<LazyRoute><SystemsMonitorPage /></LazyRoute>} />
          <Route path="infrastructure" element={<LazyRoute><InfrastructureView /></LazyRoute>} />
          <Route path="honeypot" element={<LazyRoute><HoneypotPage /></LazyRoute>} />
          <Route path="reports" element={<LazyRoute><ReportsPage /></LazyRoute>} />
          <Route path="settings" element={<ComingSoon section="settings" />} />
          <Route path="support" element={<ComingSoon section="support" />} />
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
      <div className="rounded-xl border border-neon-cyan/30 bg-bg-elevated/45 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.22em] text-neon-cyan shadow-[0_0_18px_-8px_rgba(0,212,255,0.65)]">
        loading module...
      </div>
    </div>
  );
}

function AppShell() {
  const [mode, setMode] = useState('autonomous');
  const location = useLocation();

  return (
    <>
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
















function DashboardView() {
  return (
    <div
      className="flex-1 min-h-0 grid gap-3 p-3
                 grid-cols-1 grid-rows-none auto-rows-min
                 lg:grid-cols-4 lg:grid-rows-3 lg:auto-rows-auto">

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.0 }}
        className="min-h-0 lg:col-span-2 lg:row-start-1">
        <ThreatFeedPanel />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.05 }}
        className="min-h-0 lg:col-start-3 lg:row-start-1">
        <RiskMeterPanel />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.1 }}
        className="min-h-0 lg:col-start-4 lg:row-span-3 lg:row-start-1">
        <AICopilotPanel />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.15 }}
        className="min-h-0 lg:col-span-2 lg:row-start-2">
        <AttackControlPanel />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.2 }}
        className="min-h-0 lg:col-start-3 lg:row-start-2">
        <AttackTimelinePanel />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.25 }}
        className="min-h-0 lg:col-span-3 lg:row-start-3">
        <SystemsOverviewPanel />
      </motion.div>
    </div>);

}