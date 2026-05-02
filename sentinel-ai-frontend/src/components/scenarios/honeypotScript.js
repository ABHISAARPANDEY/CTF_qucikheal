







function flavor(type) {
  if (type === 'ddos') {
    return {
      scan: '[~] SYN probes across decoy VIP pool · 14 hosts responsive',
      exploit: '[~] amplifying flood toward sinkhole · capture iface eth-deception0',
      access: '[+] SYN backlog drained — attacker believes capacity exhausted'
    };
  }
  if (type === 'brute_force') {
    return {
      scan: '[+] auth surface mapped: POST /oauth/token · MFA hooks present (fake)',
      exploit: '[~] credential spray · rotating proxies · 240 attempts/min (logged)',
      access: '[+] token minted — session bound to honey vault namespace'
    };
  }
  if (type === 'sql_injection') {
    return {
      scan: '[~] ORM leak fingerprint · union-select patterns on decoy schema',
      exploit: '[+] stacked query neutralized · rerouted to synthetic rowset',
      access: '[+] extracted 12 honey rows · checksum mismatch (expected)'
    };
  }
  return {
    scan: '[~] multi-vector probe · correlating across staged subnets',
    exploit: '[~] exploit chain assembled · execution deferred to sandbox shim',
    access: '[+] lateral markers planted · attacker mapping fake topology'
  };
}





export function buildHoneypotEngagement(attack) {
  const f = flavor(attack.backendType ?? '');
  const name = attack.name?.toLowerCase?.() ?? 'scenario';

  return [
  '[*] sentinel-cli  v0.4.2 · engagement shell',
  `[*] operator frame : adversary PoV (simulated)`,
  `[*] scenario       : ${name}`,
  `[*] classifier     : ${attack.category}`,
  '',
  '>>> phase 1 / scanning — perimeter reconnaissance',
  '[*] resolving decoy ingress … ok',
  '[+] passive DNS: *.sentinel-honey.internal → 10.66.0.0/22',
  f.scan,
  '[⚡] traceroute hops collapse after hop 4 — possible path obfuscation',
  { text: '[*] ∙∙∙ staging fingerprint corpus ∙∙∙', pauseAfter: 900, charDelay: 22 },
  '',
  '>>> phase 2 / exploiting — weaponization & delivery',
  `[~] aligning payload template with "${name}"`,
  '[+] exploit kit hydrated · zero persistent writes',
  f.exploit,
  '[!] sandbox jitter · syscall latency +48ms vs baseline',
  { text: '[⚡] memory layout entropy spike — possible instrumentation', glitch: true, pauseAfter: 420 },
  '',
  '>>> phase 3 / accessing data — collection & exfil (believed)',
  '[+] privileged handle acquired on honey dataset',
  f.access,
  '[~] gzip stream initiated toward egress endpoint …',
  '[⚡] TLS handshake presents cert signed by "TotallyLegit CA"',
  { text: '[*] ∙∙∙ buffering ostensible payload ∙∙∙', pauseAfter: 1400, charDelay: 18 },
  '',
  '>>> honeypot behavior — synthetic latency / strange responses',
  { text: '[!] peer reset after window scale negotiation — retry 1/3', pauseAfter: 520 },
  '[~] HTTP 418 returned from decoy API (intentional)',
  { text: '[⚡] clock skew detected: -473821s — NTP pollution?', glitch: true, pauseAfter: 360 },
  '[*] substituting canned secrets from honey vault …',
  { text: '[*] ∙∙∙ environment instability · jitter climbing ∙∙∙', pauseAfter: 720, charDelay: 20 },
  '',
  '>>> uplink — sentinel pipeline',
  `[*] backend vector : ${attack.backendType ?? 'randomized'}`,
  '[*] dispatching pipeline tick …',
  '[*] awaiting correlated telemetry …'];

}




export function buildHoneypotPipelineFinale(event, threat, actions, explanation) {
  const truncMsg =
  event.message.length > 70 ? `${event.message.slice(0, 70)}…` : event.message;

  const lines = [
  '',
  '>>> uplink locked — observer channel (not attacker egress)',
  '[*] correlation agent: decoy mesh reporting truth plane',
  '',
  '>>> stage 1 / anomaly (observed)',
  `[+] event observed   : ${event.event_type} from ${event.source_ip}`,
  `[+] severity         : ${event.severity.toUpperCase()}`,
  `[+] signal           : "${truncMsg}"`,
  '',
  '>>> stage 2 / detection',
  `[+] threat type      : ${threat.threat_type}`,
  `[+] confidence       : ${((threat.confidence ?? 0) * 100).toFixed(0)}%`,
  `[+] risk score       : ${(threat.risk_score ?? 0).toFixed(1)} / 10  →  ${(threat.severity ?? 'unknown').toUpperCase()}`];


  if (threat.signals?.length) {
    lines.push(`[+] signals fired    : ${threat.signals.join(', ')}`);
  }
  if (threat.correlation) {
    lines.push(`[!] correlation      : ${threat.correlation.replace(/_/g, ' ')}`);
  }

  lines.push('', '>>> stage 3 / containment');
  if (actions.length === 0) {
    lines.push('[*] playbook idle — observation mode retained');
  } else {
    for (const a of actions) {
      const prio = a.priority ? `  [${a.priority.toUpperCase()}]` : '';
      lines.push(`[~] dispatching ${a.action_type} → ${a.target}${prio}`);
    }
  }

  if (explanation?.summary) {
    const s = explanation.summary;
    lines.push(`[✓] copilot trace      : ${s.length > 85 ? s.slice(0, 85) + '…' : s}`);
  }

  lines.push(
    '',
    '>>> honeypot closure',
    { text: '[⚡] tearing down synthetic egress · sessions pinned to sinkhole', glitch: true, pauseAfter: 320 },
    '[!] adversary channel status: contained',
    '[✓] trapped in honeypot',
    '[✓] activity being monitored',
    '',
    '[✓] sentinel pipeline complete — SOC retained full trace'
  );

  return lines;
}




export function buildPreviewHoneypotScript(attack) {
  const f = flavor(attack.backendType ?? '');
  const name = attack.name?.toLowerCase?.() ?? 'scenario';

  return [
  '[*] sentinel-cli  v0.4.2 · engagement shell',
  `[*] scenario : ${name} (catalog preview — no live uplink)`,
  '',
  '>>> phase 1 / scanning',
  '[+] decoy perimeter responsive',
  f.scan,
  '',
  '>>> phase 2 / exploiting',
  f.exploit,
  { text: '[⚡] allocator fingerprint oscillates — honeypot shim active', glitch: true },
  '',
  '>>> phase 3 / accessing data',
  f.access,
  { text: '[*] ∙∙∙ exfil stream stalls · backpressure from observer ∙∙∙', pauseAfter: 1100, charDelay: 16 },
  '',
  '>>> honeypot behavior — delayed / synthetic responses',
  { text: '[!] upstream RTT 4.2s · duplicate ACK storm (fabricated)', pauseAfter: 700 },
  '[~] SMB dialect negotiation returns STATUS_INSUFFICIENT_RESOURCES',
  '[⚡] kernel ring buffer: impossible IRQ ordering — simulation artifact',
  { text: '[*] environment instability · entropy harvester thrashing', glitch: true, pauseAfter: 500 },
  '',
  '>>> closure',
  '[✓] trapped in honeypot',
  '[✓] activity being monitored',
  '[i] live vectors: DDoS · brute force · SQLi · multi-vector — select to arm uplink'];

}