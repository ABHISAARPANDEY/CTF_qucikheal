const preloaders = {
  '/systems': () => import('../components/systems/SystemsMonitorPage'),
  '/infrastructure': () => import('../components/infrastructure/InfrastructureView'),
  '/honeypot': () => import('../components/honeypot/HoneypotPage'),
  '/reports': () => import('../components/reports/ReportsPage')
};

const loaded = new Set();

export function preloadRoute(path) {
  const fn = preloaders[path];
  if (!fn || loaded.has(path)) return;
  loaded.add(path);
  void fn();
}

export function preloadLikelyRoutes() {
  preloadRoute('/systems');
  preloadRoute('/infrastructure');
  preloadRoute('/honeypot');
  preloadRoute('/reports');
}
