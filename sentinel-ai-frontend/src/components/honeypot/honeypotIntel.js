












export const ATTACK_TYPES = [
'ddos',
'brute_force',
'sql_injection',
'insider',
'multi_stage'];



export const ATTACK_META = {
  ddos: {
    label: 'DDoS Flood',
    short: 'DDOS',
    blurb: 'Volumetric HTTP flood saturating the edge gateway.',
    accent: 'orange',
    banner: 'volumetric flood'
  },
  brute_force: {
    label: 'Brute Force / Login Flood',
    short: 'BRUTE',
    blurb: 'Credential stuffing escalating into MFA bypass attempts.',
    accent: 'red',
    banner: 'credential stuffing'
  },
  sql_injection: {
    label: 'SQL Injection',
    short: 'SQLi',
    blurb: 'Boolean-blind SQLi enumerating the accounts schema.',
    accent: 'cyan',
    banner: 'SQL injection probe'
  },
  insider: {
    label: 'Insider Threat',
    short: 'INSIDER',
    blurb: 'Privileged user abusing legitimate APIs after-hours.',
    accent: 'violet',
    banner: 'insider data access'
  },
  multi_stage: {
    label: 'Multi-stage Kill Chain',
    short: 'CHAIN',
    blurb: 'Recon → access → lateral → exfil → persistence (full APT).',
    accent: 'green',
    banner: 'kill-chain engagement'
  }
};



const _IP_POOLS = {
  ddos: [194, 87, 213, 156, 89],
  brute_force: [185, 45, 77, 203, 38],
  sql_injection: [142, 51, 23, 11, 178],
  insider: [10],
  multi_stage: [101, 89, 142, 200, 8]
};


export function synthesizeAttackerIp(attackType, runId = '') {
  const pool = _IP_POOLS[attackType] ?? [203];
  const seed = (runId + attackType).
  split('').
  reduce((h, c) => h * 31 + c.charCodeAt(0) >>> 0, 7);

  const a = pool[seed % pool.length];

  if (a === 10) {
    return `10.${(seed >> 4) % 200 + 10}.${(seed >> 8) % 200 + 1}.${(seed >> 12) % 240 + 6}`;
  }
  return `${a}.${(seed >> 4) % 256}.${(seed >> 8) % 256}.${(seed >> 12) % 254 + 1}`;
}











export const PATTERN_CATALOG = [
{
  id: 'scanning',
  label: 'Recon & Scanning',
  accent: 'cyan',
  description: 'Endpoint enumeration, port probing, schema discovery.',
  keywords: ['recon', 'scan', 'enum', 'probe', 'discover', 'fingerprint', 'subdomain']
},
{
  id: 'credential_theft',
  label: 'Credential Theft',
  accent: 'red',
  description: 'Brute force, credential stuffing, MFA bypass attempts.',
  keywords: ['credential', 'login', 'password', 'mfa', 'totp', 'oauth', 'token', 'session', 'auth']
},
{
  id: 'sql_injection',
  label: 'SQL Injection',
  accent: 'orange',
  description: 'Malicious SQL crafted to extract or manipulate data.',
  keywords: ['sql', 'union', 'sqli', 'payload', 'information_schema', 'select', 'extraction']
},
{
  id: 'data_exfiltration',
  label: 'Data Exfiltration',
  accent: 'violet',
  description: 'Bulk reads or transfers of sensitive records.',
  keywords: ['exfil', 'bulk', 'extract', 'dump', 'pii', 'sensitive', 'rows so far']
},
{
  id: 'privilege_escalation',
  label: 'Privilege Escalation',
  accent: 'red',
  description: 'Attempts to obtain higher-level access.',
  keywords: ['privilege', 'escalation', 'grant', 'sudo', 'role', 'admin']
},
{
  id: 'lateral_movement',
  label: 'Lateral Movement',
  accent: 'orange',
  description: 'Pivoting into adjacent systems within the cluster.',
  keywords: ['lateral', 'pivot', 'backpressure', 'cluster', 'peer']
},
{
  id: 'persistence',
  label: 'Persistence',
  accent: 'violet',
  description: 'Implants, miners, or backdoors deployed for longevity.',
  keywords: ['persistence', 'miner', 'backdoor', 'implant', 'plant', 'reinstall']
},
{
  id: 'insider_abuse',
  label: 'Insider Abuse',
  accent: 'red',
  description: 'Privileged user bypassing normal controls.',
  keywords: ['insider', 'off-hours', 'unusual', 'bypass', 'rate limit']
}];


const _PATTERNS_BY_KEYWORD = (() => {
  const out = [];
  for (const p of PATTERN_CATALOG) {
    for (const kw of p.keywords) out.push({ kw: kw.toLowerCase(), id: p.id });
  }
  return out;
})();











export function detectPatterns(scenarioEvents, honeypotAnalyses = []) {
  if (!scenarioEvents?.length && !honeypotAnalyses?.length) return [];

  const acc = {};

  const sorted = [...scenarioEvents].sort((a, b) => idxOf(a) - idxOf(b));
  const sevOrder = { info: 0, warning: 1, high: 2, critical: 3 };

  for (const evt of sorted) {
    const text = (evt.label ?? '').toLowerCase();
    if (!text) continue;
    const hit = new Set();
    for (const { kw, id } of _PATTERNS_BY_KEYWORD) {
      if (text.includes(kw)) hit.add(id);
    }
    for (const id of hit) {
      const cur = acc[id] ?? {
        id,
        hits: 0,
        severity: 'info',
        firstSeenAt: evt.ts ? Date.parse(evt.ts) : Date.now()
      };
      cur.hits += 1;
      if (sevOrder[evt.severity] > sevOrder[cur.severity]) {
        cur.severity = evt.severity;
      }
      acc[id] = cur;
    }
  }




  for (const h of honeypotAnalyses ?? []) {
    const text = `${h?.data?.pattern ?? ''}`.toLowerCase();
    if (!text) continue;
    const matched = PATTERN_CATALOG.find((p) =>
    p.keywords.some((kw) => text.includes(kw))
    );
    const id = matched?.id ?? 'data_exfiltration';
    const cur = acc[id] ?? {
      id,
      hits: 0,
      severity: 'info',
      firstSeenAt: h?.ts ? Date.parse(h.ts) : Date.now()
    };
    cur.hits += 1;
    const risk = String(h?.data?.risk ?? 'low').toLowerCase();
    const mapped =
    risk === 'critical' ?
    'critical' :
    risk === 'high' ?
    'high' :
    risk === 'medium' ?
    'warning' :
    'info';
    if (sevOrder[mapped] > sevOrder[cur.severity]) cur.severity = mapped;
    acc[id] = cur;
  }

  return Object.values(acc).
  sort((a, b) => a.firstSeenAt - b.firstSeenAt).
  map((entry) => {
    const def = PATTERN_CATALOG.find((p) => p.id === entry.id);
    return {
      id: entry.id,
      label: def?.label ?? entry.id,
      accent: def?.accent ?? 'cyan',
      description: def?.description ?? '',
      hits: entry.hits,
      severity: entry.severity,
      firstSeenAt: entry.firstSeenAt
    };
  });
}



const SEVERITY_PREFIX = {
  info: '[*]',
  warning: '[~]',
  high: '[!]',
  critical: '[✗]'
};

const SEVERITY_CHAR_DELAY = {
  info: 14,
  warning: 14,
  high: 10,
  critical: 8
};






export function buildHoneypotScript(
attackType,
attackerIp,
scenarioEvents,
honeypotActivities = [],
honeypotAnalyses = [])
{
  const meta = ATTACK_META[attackType] ?? ATTACK_META.ddos;
  const lines = [
  '[*] sentinel-cli  v0.4.2 · honeypot observer shell',
  '[*] frame source  : decoy mesh (truth plane)',
  `[*] adversary src : ${attackerIp}`,
  `[*] vector        : ${meta.short.toLowerCase()} — ${meta.blurb.toLowerCase()}`,
  '',
  '>>> ingress detected — channel pinned to sinkhole'];




  lines.push(...openingLines(attackType));

  if (scenarioEvents.length === 0 && honeypotActivities.length === 0 && honeypotAnalyses.length === 0) {
    lines.push(
      '',
      '[*] awaiting orchestrator handshake …',
      '[*] (no live events yet — press TRIGGER to engage)'
    );
    return lines;
  }


  const sorted = [...scenarioEvents].sort((a, b) => idxOf(a) - idxOf(b));
  const hpAct = [...honeypotActivities].sort((a, b) => idxOf(a) - idxOf(b));
  const hpAna = [...honeypotAnalyses].sort((a, b) => idxOf(a) - idxOf(b));

  let lastStage = null;
  for (const evt of sorted) {
    if (evt.stage !== lastStage) {
      lines.push('');
      lines.push(
        `>>> stage ${evt.stage}/${evt.total_stages} · ${evt.severity.toUpperCase()}`
      );
      lastStage = evt.stage;
    }
    const prefix = SEVERITY_PREFIX[evt.severity] ?? '[*]';
    const sysTag = evt.system ? `${evt.system.padEnd(20)} ` : ' '.repeat(21);
    lines.push({
      text: `${prefix} ${sysTag}${evt.label}`,
      charDelay: SEVERITY_CHAR_DELAY[evt.severity] ?? 14,
      pauseAfter: evt.severity === 'critical' ? 320 : 200,
      glitch: evt.severity === 'critical'
    });
  }

  if (hpAct.length > 0 || hpAna.length > 0) {
    lines.push('');
    lines.push('>>> honeypot behavior stream');
    for (const evt of hpAct) {
      lines.push({
        text: `[~] activity        : ${String(evt?.data?.action ?? 'unknown').replace(/_/g, ' ')}`,
        charDelay: 12,
        pauseAfter: 180
      });
    }
    for (const evt of hpAna) {
      lines.push({
        text: `[!] analysis        : ${evt?.data?.pattern ?? 'unknown'} · risk ${String(evt?.data?.risk ?? 'low').toUpperCase()}`,
        charDelay: 11,
        pauseAfter: 180,
        glitch: String(evt?.data?.risk ?? '').toLowerCase() === 'critical'
      });
    }
  }


  const last = sorted[sorted.length - 1];
  if (last && last.stage === last.total_stages) {
    lines.push(
      '',
      '>>> honeypot closure',
      { text: '[⚡] adversary believes engagement succeeded — vault is honey-data', glitch: true, pauseAfter: 360 },
      '[!] trapped in honeypot',
      '[✓] activity being monitored',
      '[✓] full session recorded — handing off to SOC observer plane'
    );
  }

  return lines;
}


function openingLines(attackType) {
  if (attackType === 'ddos') {
    return [
    '[~] SYN backlog drained — attacker believes capacity exhausted',
    '[*] capture iface eth-deception0 — packets pinned to sinkhole'];

  }
  if (attackType === 'brute_force') {
    return [
    '[~] auth surface mapped: POST /oauth/token (decoy)',
    '[*] credential responses minted from honey vault'];

  }
  if (attackType === 'sql_injection') {
    return [
    '[~] ORM leak fingerprint accepted · attacker thinks DB is exposed',
    '[*] decoy schema returns synthetic rowsets'];

  }
  if (attackType === 'insider') {
    return [
    '[~] privileged session originated from VPN range 10.66.4.0/22',
    '[*] off-hours activity — sentinel raised silent observation'];

  }
  if (attackType === 'multi_stage') {
    return [
    '[~] kill chain engaged — multiple decoy systems instrumented',
    '[*] adversary believes lateral movement is succeeding'];

  }
  return [];
}


















export function buildTimeline(attackType, scenarioEvents) {
  const sorted = scenarioEvents.length ?
  [...scenarioEvents].sort((a, b) => idxOf(a) - idxOf(b)) :
  [];
  const sevOrder = { info: 0, warning: 1, high: 2, critical: 3 };
  const peakSeverity = sorted.reduce(
    (acc, e) => sevOrder[e.severity] > sevOrder[acc] ? e.severity : acc,
    'info'
  );
  const last = sorted[sorted.length - 1];
  const finished = !!last && last.stage === last.total_stages;

  const tsOf = (evt) => evt?.ts ? Date.parse(evt.ts) : null;
  const first = sorted[0];
  const firstWarning = sorted.find((e) => e.severity !== 'info');
  const firstHigh = sorted.find((e) => sevOrder[e.severity] >= 2);

  return [
  {
    id: 'attack',
    label: 'Attack',
    sub: 'Inbound vector detected',
    icon: 'crosshair',
    status: !sorted.length ? 'pending' : firstWarning ? 'complete' : 'active',
    ts: tsOf(first)
  },
  {
    id: 'trap',
    label: 'Trap',
    sub: 'Adversary contained in honeypot',
    icon: 'shield',
    status:
    !sorted.length ?
    'pending' :
    peakSeverity === 'critical' || finished ?
    'complete' :
    'active',
    ts: tsOf(firstWarning ?? first)
  },
  {
    id: 'analysis',
    label: 'Analysis',
    sub: 'Behaviour fingerprinted · pattern catalog updated',
    icon: 'microscope',
    status:
    !sorted.length ?
    'pending' :
    finished ?
    'complete' :
    firstHigh ?
    'active' :
    'pending',
    ts: tsOf(firstHigh)
  }];

}




function idxOf(evt) {
  if (typeof evt?.stage === 'number') return evt.stage;
  if (evt?.ts) return Date.parse(evt.ts);
  return 0;
}