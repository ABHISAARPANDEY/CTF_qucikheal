














export const CLUSTERS = [
{
  id: 'edge',
  name: 'Cluster A · Edge & Identity',
  blurb: 'Public perimeter, identity and ingress control plane.',
  accent: 'cyan',
  systemIds: ['api_gateway', 'auth_service']
},
{
  id: 'payments',
  name: 'Cluster B · Payments Rail',
  blurb: 'Transaction execution and anti-fraud scoring services.',
  accent: 'green',
  systemIds: ['tx_service', 'fraud_service']
},
{
  id: 'data',
  name: 'Cluster C · Data Plane',
  blurb: 'Ledger persistence, analytics and replication.',
  accent: 'orange',
  systemIds: ['database', 'analytics_service']
},
{
  id: 'ops',
  name: 'Cluster D · Operations',
  blurb: 'Monitoring, backup and scheduler agents.',
  accent: 'violet',
  systemIds: ['monitoring_service', 'backup_service']
},
{
  id: 'integration',
  name: 'Cluster E · Integration',
  blurb: 'Notification and external banking adapters.',
  accent: 'cyan',
  systemIds: ['notification_service', 'integration_gateway']
}];


export const SYSTEM_IDS = [
'api_gateway',
'auth_service',
'tx_service',
'database',
'fraud_service',
'analytics_service',
'monitoring_service',
'backup_service',
'notification_service',
'integration_gateway'];



















export const SYSTEMS = {
  api_gateway: {
    id: 'api_gateway',
    name: 'API Gateway',
    kind: 'Edge gateway',
    accent: 'cyan',
    cluster: 'edge',
    icon: 'globe',
    baseCpu: 28,
    baseRps: 1840,
    threatTypes: ['ddos'],
    processes: [
    { pid: 'nginx', label: 'nginx', role: 'edge proxy' },
    { pid: 'gateway-edge', label: 'gateway-edge', role: 'router' },
    { pid: 'rate-limiter', label: 'rate-limiter', role: 'guard' },
    { pid: 'tls-terminator', label: 'tls-terminator', role: 'crypto' }],

    malicious: {
      pid: 'rogue_curl_flood',
      label: 'rogue_curl_flood',
      role: 'foreign · flood',
      summary: 'Synthetic HTTP flood saturating edge listener pool'
    },
    regions: ['eu-west-1', 'us-east-2']
  },

  auth_service: {
    id: 'auth_service',
    name: 'Auth Service',
    kind: 'Identity provider',
    accent: 'violet',
    cluster: 'edge',
    icon: 'lock',
    baseCpu: 22,
    baseRps: 640,
    threatTypes: ['brute_force'],
    processes: [
    { pid: 'auth_service', label: 'auth_service', role: 'idp' },
    { pid: 'oauth-proxy', label: 'oauth-proxy', role: 'proxy' },
    { pid: 'session-cache', label: 'session-cache', role: 'cache' },
    { pid: 'mfa-vault', label: 'mfa-vault', role: 'secrets' }],

    malicious: {
      pid: 'cred_stuffer',
      label: 'cred_stuffer.py',
      role: 'foreign · brute',
      summary: 'Credential-stuffing burst across rotating proxies'
    },
    regions: ['eu-west-1']
  },

  tx_service: {
    id: 'tx_service',
    name: 'Transaction Service',
    kind: 'Payments engine',
    accent: 'green',
    cluster: 'core',
    icon: 'banknote',
    baseCpu: 34,
    baseRps: 920,
    threatTypes: ['sql_injection', 'tx_replay'],
    processes: [
    { pid: 'tx-engine', label: 'tx-engine', role: 'core' },
    { pid: 'payment-router', label: 'payment-router', role: 'router' },
    { pid: 'ledger-sync', label: 'ledger-sync', role: 'sync' },
    { pid: 'fraud-scorer', label: 'fraud-scorer', role: 'ml' }],

    malicious: {
      pid: 'tx_replay_worker',
      label: 'tx_replay_worker',
      role: 'foreign · replay',
      summary: 'Replaying signed transaction envelopes with mutated nonces'
    },
    regions: ['eu-west-1', 'us-east-2']
  },
  fraud_service: {
    id: 'fraud_service',
    name: 'Fraud Service',
    kind: 'Real-time scoring',
    accent: 'green',
    cluster: 'payments',
    icon: 'lock',
    baseCpu: 26,
    baseRps: 760,
    threatTypes: ['brute_force', 'insider'],
    processes: [
    { pid: 'fraud-core', label: 'fraud-core', role: 'ml' },
    { pid: 'feature-stream', label: 'feature-stream', role: 'stream' },
    { pid: 'risk-cache', label: 'risk-cache', role: 'cache' },
    { pid: 'policy-engine', label: 'policy-engine', role: 'rule' }],
    malicious: {
      pid: 'model_poisoner',
      label: 'model_poisoner.py',
      role: 'foreign · model',
      summary: 'Injected adversarial signals into fraud scoring stream'
    },
    regions: ['eu-west-1']
  },

  database: {
    id: 'database',
    name: 'Core Database',
    kind: 'Primary ledger',
    accent: 'orange',
    cluster: 'core',
    icon: 'database',
    baseCpu: 30,
    baseRps: 2680,
    threatTypes: ['sql_injection'],
    processes: [
    { pid: 'db_engine', label: 'db_engine', role: 'rdbms' },
    { pid: 'postgresql', label: 'postgresql', role: 'primary' },
    { pid: 'pgbouncer', label: 'pgbouncer', role: 'pool' },
    { pid: 'wal-archiver', label: 'wal-archiver', role: 'archive' }],

    malicious: {
      pid: 'sqli_probe',
      label: 'sqli_probe.sh',
      role: 'foreign · sqli',
      summary: 'Boolean-blind SQLi probing /accounts/balance endpoint'
    },
    regions: ['eu-west-1']
  },
  analytics_service: {
    id: 'analytics_service',
    name: 'Analytics Service',
    kind: 'Warehouse worker',
    accent: 'orange',
    cluster: 'data',
    icon: 'database',
    baseCpu: 24,
    baseRps: 520,
    threatTypes: ['sql_injection', 'data_exfiltration'],
    processes: [
    { pid: 'etl-worker', label: 'etl-worker', role: 'etl' },
    { pid: 'warehouse-sync', label: 'warehouse-sync', role: 'sync' },
    { pid: 'metrics-rollup', label: 'metrics-rollup', role: 'rollup' },
    { pid: 'dash-cache', label: 'dash-cache', role: 'cache' }],
    malicious: {
      pid: 'bulk_dump',
      label: 'bulk_dump.sh',
      role: 'foreign · exfil',
      summary: 'Mass export from analytics snapshots to unknown destination'
    },
    regions: ['eu-west-1']
  },
  monitoring_service: {
    id: 'monitoring_service',
    name: 'Monitoring Service',
    kind: 'Observability',
    accent: 'violet',
    cluster: 'ops',
    icon: 'globe',
    baseCpu: 16,
    baseRps: 220,
    threatTypes: ['ddos', 'anomaly'],
    processes: [
    { pid: 'metrics-ingest', label: 'metrics-ingest', role: 'ingest' },
    { pid: 'alert-router', label: 'alert-router', role: 'router' },
    { pid: 'log-indexer', label: 'log-indexer', role: 'index' },
    { pid: 'retention-gc', label: 'retention-gc', role: 'gc' }],
    malicious: {
      pid: 'alert_disabler',
      label: 'alert_disabler.bin',
      role: 'foreign · tamper',
      summary: 'Attempt to suppress anomaly alerts and rotate audit files'
    },
    regions: ['eu-west-1']
  },
  backup_service: {
    id: 'backup_service',
    name: 'Backup Service',
    kind: 'Snapshot scheduler',
    accent: 'violet',
    cluster: 'ops',
    icon: 'database',
    baseCpu: 14,
    baseRps: 160,
    threatTypes: ['insider', 'malware'],
    processes: [
    { pid: 'snapshot-daemon', label: 'snapshot-daemon', role: 'snapshot' },
    { pid: 'restore-agent', label: 'restore-agent', role: 'restore' },
    { pid: 'vault-uploader', label: 'vault-uploader', role: 'uploader' },
    { pid: 'checksumd', label: 'checksumd', role: 'integrity' }],
    malicious: {
      pid: 'encryptor',
      label: 'encryptor.exe',
      role: 'foreign · ransomware',
      summary: 'Suspicious backup encryption job with unknown key origin'
    },
    regions: ['eu-west-1']
  },
  notification_service: {
    id: 'notification_service',
    name: 'Notification Service',
    kind: 'Alert / customer comms',
    accent: 'cyan',
    cluster: 'integration',
    icon: 'banknote',
    baseCpu: 18,
    baseRps: 420,
    threatTypes: ['phishing', 'brute_force'],
    processes: [
    { pid: 'mail-worker', label: 'mail-worker', role: 'mail' },
    { pid: 'sms-bridge', label: 'sms-bridge', role: 'sms' },
    { pid: 'template-cache', label: 'template-cache', role: 'cache' },
    { pid: 'delivery-retry', label: 'delivery-retry', role: 'retry' }],
    malicious: {
      pid: 'phish_sender',
      label: 'phish_sender.py',
      role: 'foreign · phishing',
      summary: 'Outbound campaign detected against internal employee aliases'
    },
    regions: ['eu-west-1', 'ap-south-1']
  },
  integration_gateway: {
    id: 'integration_gateway',
    name: 'Integration Gateway',
    kind: 'Partner API bridge',
    accent: 'cyan',
    cluster: 'integration',
    icon: 'globe',
    baseCpu: 22,
    baseRps: 680,
    threatTypes: ['ddos', 'sql_injection'],
    processes: [
    { pid: 'partner-proxy', label: 'partner-proxy', role: 'proxy' },
    { pid: 'transformer', label: 'transformer', role: 'transform' },
    { pid: 'schema-guard', label: 'schema-guard', role: 'guard' },
    { pid: 'token-relay', label: 'token-relay', role: 'relay' }],
    malicious: {
      pid: 'signed_update_exe',
      label: 'bank_update.exe',
      role: 'foreign · trojan',
      summary: 'Fake signed updater execution path opened external C2 channel'
    },
    regions: ['us-east-2']
  }
};






export function resolveTargetSystem(threat) {
  if (!threat?.threat_type) return null;
  for (const id of SYSTEM_IDS) {
    if (SYSTEMS[id].threatTypes.includes(threat.threat_type)) return id;
  }
  return 'tx_service';
}







const LATERAL = {
  api_gateway: ['auth_service'],
  auth_service: ['api_gateway'],
  tx_service: ['fraud_service', 'database'],
  fraud_service: ['tx_service'],
  database: ['analytics_service', 'tx_service'],
  analytics_service: ['database'],
  monitoring_service: ['backup_service'],
  backup_service: ['monitoring_service'],
  notification_service: ['integration_gateway'],
  integration_gateway: ['notification_service']
};

export function lateralSystems(systemId) {
  return LATERAL[systemId] ?? [];
}




export function describeAnomaly(threat, event, systemId) {
  if (event?.message) {
    const m = event.message;
    return m.length > 140 ? `${m.slice(0, 138)}…` : m;
  }
  const sys = SYSTEMS[systemId];
  if (!sys) return null;
  if (threat?.threat_type) {
    const human = String(threat.threat_type).replace(/_/g, ' ');
    return `${sys.name} under ${human} — risk ${threat.risk_score?.toFixed?.(1) ?? '—'}`;
  }
  return `${sys.name} elevated risk`;
}