// Realistic decoy-capture transcripts.
//
// Lines are written to read like a real captured attacker session interleaved
// with host syslog: a shell prompt for the adversary's own input, then
// sshd/nginx/auth-svc/kernel log lines the honeypot recorded. The Terminal
// component colours lines by syslog severity keywords (WARN/ERR/CRIT/…) and
// by the `user@host:~#` prompt pattern — no theatrical markup.

const HOST = {
  ddos: 'edge-gw-02',
  brute_force: 'auth-01',
  sql_injection: 'db-primary',
  insider: 'db-primary',
  multi_stage: 'edge-gw-02'
};

function ts(offsetSec = 0) {
  const d = new Date(Date.now() + offsetSec * 1000);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

function flavor(type) {
  if (type === 'ddos') {
    return [
      'kernel: [ nf_conntrack ] table full, dropping packet',
      'nginx[1182]: WARN 4092 pending connections, worker_connections exhausted',
      'haproxy[880]: NOTICE backend web_pool has no available server, sinkholing',
      'sentinel-sensor: SYN flood 1.9 Mpps from ~48210 sources -> 203.0.113.10:443'
    ];
  }
  if (type === 'brute_force') {
    return [
      "sshd[3391]: Failed password for invalid user admin from 45.146.164.12 port 51044 ssh2",
      "sshd[3391]: Failed password for root from 45.146.164.71 port 51120 ssh2",
      "auth-svc[2214]: WARN 214 failed logins for 'root' from /24 45.146.164.0 in 60s",
      "sshd[3391]: Accepted password for svc_deploy from 45.146.164.12 port 51180 ssh2 (decoy)"
    ];
  }
  if (type === 'sql_injection') {
    return [
      "nginx[1182]: 45.9.148.33 \"GET /accounts?id=1' OR '1'='1 HTTP/1.1\" 200",
      'postgres[771]: LOG statement: SELECT * FROM accounts WHERE id=1 UNION SELECT usename,passwd FROM pg_shadow',
      'db-firewall[512]: WARN union-based payload matched rule SQLI-014, rerouting to decoy schema',
      'sentinel-sensor: NOTICE 12 rows returned from honey_accounts (synthetic PII)'
    ];
  }
  if (type === 'insider') {
    return [
      "auditd[610]: type=USER_CMD msg=op=bulk_export acct=j.reyes res=success",
      'postgres[771]: LOG duration: 8841 ms  statement: COPY customer_accounts TO STDOUT',
      'db-firewall[512]: WARN off-hours bulk read 2.1M rows by j.reyes via vpn-pool-7',
      'sentinel-sensor: NOTICE egress 198.51.100.42:8443 flagged — data staged in decoy bucket'
    ];
  }
  return [
    'sentinel-sensor: recon sweep across 10.66.0.0/22, 14 decoy hosts responsive',
    "sshd[3391]: Failed password for root from 185.220.101.4 port 43110 ssh2",
    'db-firewall[512]: WARN SQLI probe on /accounts/balance after auth compromise',
    'sentinel-sensor: NOTICE lateral markers planted, attacker mapping fabricated topology'
  ];
}

export function buildHoneypotEngagement(attack) {
  const type = attack.backendType ?? 'multi_stage';
  const host = HOST[type] ?? 'edge-gw-02';
  const name = attack.name ?? 'scenario';
  const f = flavor(type);

  return [
    `# session captured on decoy ${host} — scenario: ${name.toLowerCase()}`,
    `# attacker point of view (simulated) · ${ts()}`,
    '',
    '>>> reconnaissance',
    `root@${host}:~# whoami && id`,
    'root  uid=0(root) gid=0(root) groups=0(root)',
    `root@${host}:~# nmap -sS -p- 10.66.0.12`,
    'Starting Nmap 7.94 ( https://nmap.org )',
    'Nmap scan report for 10.66.0.12  (decoy)',
    'PORT     STATE SERVICE',
    '22/tcp   open  ssh',
    '443/tcp  open  https',
    '5432/tcp open  postgresql',
    { text: f[0], pauseAfter: 600 },
    '',
    '>>> exploitation',
    { text: f[1], pauseAfter: 300 },
    { text: f[2], pauseAfter: 300 },
    'sentinel-sensor: NOTICE payload executed in sandbox shim — zero persistent writes',
    '',
    '>>> collection (believed successful)',
    `root@${host}:~# cat /var/lib/app/secrets.env`,
    'DB_PASSWORD=hunter2-DECOY',
    'STRIPE_KEY=sk_live_0000DECOY0000',
    { text: f[3], pauseAfter: 500 },
    'sentinel-sensor: WARN attacker exfiltrating honey credentials (tracked)',
    '',
    '>>> uplink — sentinel pipeline',
    `sentinel: forwarding decoy telemetry for vector "${type}"`,
    'sentinel: awaiting correlated detection tick …'
  ];
}

export function buildHoneypotPipelineFinale(event, threat, actions, explanation) {
  const truncMsg =
    event.message.length > 80 ? `${event.message.slice(0, 80)}…` : event.message;

  const lines = [
    '',
    '>>> sentinel correlation (truth plane)',
    `sentinel: INFO event ${event.event_type} from ${event.source_ip}`,
    `sentinel: INFO raw "${truncMsg}"`,
    `sentinel: detection ${threat.threat_type} · risk ${(threat.risk_score ?? 0).toFixed(1)}/10 · conf ${((threat.confidence ?? 0) * 100).toFixed(0)}%`
  ];

  if (threat.signals?.length) {
    lines.push(`sentinel: signals ${threat.signals.join(', ')}`);
  }
  if (threat.correlation) {
    lines.push(`sentinel: WARN correlation ${threat.correlation.replace(/_/g, ' ')}`);
  }

  lines.push('', '>>> containment');
  if (!actions.length) {
    lines.push('sentinel: NOTICE playbook idle — observation retained');
  } else {
    for (const a of actions) {
      const prio = a.priority ? ` [${a.priority.toUpperCase()}]` : '';
      lines.push(`sentinel: dispatch ${a.action_type} -> ${a.target}${prio}`);
    }
  }

  if (explanation?.summary) {
    const s = explanation.summary;
    lines.push(`sentinel: copilot ${s.length > 90 ? s.slice(0, 90) + '…' : s}`);
  }

  lines.push(
    '',
    '>>> closure',
    'sentinel: NOTICE decoy session contained, egress pinned to sinkhole',
    'sentinel: NOTICE full session recorded — handed to SOC observer plane'
  );

  return lines;
}

export function buildPreviewHoneypotScript(attack) {
  const type = attack.backendType ?? 'multi_stage';
  const host = HOST[type] ?? 'edge-gw-02';
  const name = attack.name ?? 'scenario';
  const f = flavor(type);

  return [
    `# catalog preview — ${name.toLowerCase()} against decoy ${host} (no live uplink)`,
    '',
    '>>> reconnaissance',
    { text: f[0], pauseAfter: 500 },
    '',
    '>>> exploitation',
    { text: f[1], pauseAfter: 300 },
    { text: f[2], pauseAfter: 300 },
    '',
    '>>> collection (synthetic)',
    { text: f[3], pauseAfter: 600 },
    'sentinel-sensor: NOTICE decoy responses fabricated — attacker sees honey data',
    '',
    '>>> closure',
    'sentinel: NOTICE session recorded, activity monitored',
    'sentinel: INFO live vectors: DDoS · brute force · SQLi · multi-vector — select to arm uplink'
  ];
}
