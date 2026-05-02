







export const CATEGORIES = {
  NETWORK: { label: 'NETWORK', rgb: '255,159,28' },
  AUTH: { label: 'AUTH', rgb: '255,59,59' },
  WEB: { label: 'WEB', rgb: '0,212,255' },
  MALWARE: { label: 'MALWARE', rgb: '167,139,250' },
  ADVANCED: { label: 'ADVANCED', rgb: '0,255,159' }
};



const RAW_ATTACKS = [

{ id: 'ddos-flood', name: 'DDoS Flood', category: 'NETWORK', active: true, backendType: 'ddos', desc: 'Volumetric flood from many distributed sources' },
{ id: 'syn-flood', name: 'SYN Flood', category: 'NETWORK' },
{ id: 'udp-reflection', name: 'UDP Reflection', category: 'NETWORK' },
{ id: 'dns-amplification', name: 'DNS Amplification', category: 'NETWORK' },
{ id: 'icmp-storm', name: 'ICMP Storm', category: 'NETWORK' },
{ id: 'port-scan', name: 'Port Scan', category: 'NETWORK' },
{ id: 'arp-spoofing', name: 'ARP Spoofing', category: 'NETWORK' },
{ id: 'bgp-hijack', name: 'BGP Hijack', category: 'NETWORK' },
{ id: 'mac-flooding', name: 'MAC Flooding', category: 'NETWORK' },
{ id: 'tcp-hijack', name: 'TCP Session Hijack', category: 'NETWORK' },


{ id: 'brute-force', name: 'Brute Force Auth', category: 'AUTH', active: true, backendType: 'brute_force', desc: 'Repeated credential probes from a single source' },
{ id: 'cred-stuffing', name: 'Credential Stuffing', category: 'AUTH' },
{ id: 'password-spray', name: 'Password Spray', category: 'AUTH' },
{ id: 'session-hijack', name: 'Session Hijack', category: 'AUTH' },
{ id: 'oauth-phish', name: 'OAuth Phishing', category: 'AUTH' },
{ id: 'kerberoast', name: 'Kerberoasting', category: 'AUTH' },
{ id: 'pass-the-hash', name: 'Pass-the-Hash', category: 'AUTH' },
{ id: 'pass-the-ticket', name: 'Pass-the-Ticket', category: 'AUTH' },
{ id: 'token-replay', name: 'Token Replay', category: 'AUTH' },
{ id: 'mfa-fatigue', name: 'MFA Fatigue', category: 'AUTH' },


{ id: 'sql-injection', name: 'SQL Injection', category: 'WEB', active: true, backendType: 'sql_injection', desc: 'Inject malicious SQL into request parameters' },
{ id: 'xss-attack', name: 'XSS Attack', category: 'WEB' },
{ id: 'csrf-exploit', name: 'CSRF Exploit', category: 'WEB' },
{ id: 'ssrf-probe', name: 'SSRF Probe', category: 'WEB' },
{ id: 'xxe-injection', name: 'XXE Injection', category: 'WEB' },
{ id: 'rce-attempt', name: 'RCE Attempt', category: 'WEB' },
{ id: 'lfi-probe', name: 'LFI Probe', category: 'WEB' },
{ id: 'dir-traversal', name: 'Directory Traversal', category: 'WEB' },
{ id: 'http-smuggling', name: 'HTTP Smuggling', category: 'WEB' },
{ id: 'web-shell', name: 'Web Shell Upload', category: 'WEB' },


{ id: 'ransomware', name: 'Ransomware Drop', category: 'MALWARE' },
{ id: 'trojan', name: 'Trojan Inject', category: 'MALWARE' },
{ id: 'rootkit', name: 'Rootkit Install', category: 'MALWARE' },
{ id: 'bootkit', name: 'Bootkit Deploy', category: 'MALWARE' },
{ id: 'cryptominer', name: 'Cryptominer', category: 'MALWARE' },
{ id: 'keylogger', name: 'Keylogger', category: 'MALWARE' },
{ id: 'rat-deploy', name: 'RAT Deploy', category: 'MALWARE' },
{ id: 'worm-spread', name: 'Worm Spread', category: 'MALWARE' },
{ id: 'wiper', name: 'Disk Wiper', category: 'MALWARE' },
{ id: 'logic-bomb', name: 'Logic Bomb', category: 'MALWARE' },


{ id: 'multi-vector', name: 'Multi-Vector Probe', category: 'ADVANCED', active: true, backendType: null, desc: 'Random-vector simulation across all attack classes' },
{ id: 'data-exfil', name: 'Data Exfiltration', category: 'ADVANCED' },
{ id: 'priv-escalation', name: 'Privilege Escalation', category: 'ADVANCED' },
{ id: 'lateral-movement', name: 'Lateral Movement', category: 'ADVANCED' },
{ id: 'smb-pivot', name: 'SMB Pivot', category: 'ADVANCED' },
{ id: 'rdp-hijack', name: 'RDP Hijack', category: 'ADVANCED' },
{ id: 'domain-trust', name: 'Domain Trust Abuse', category: 'ADVANCED' },
{ id: 'insider-threat', name: 'Insider Threat', category: 'ADVANCED' },
{ id: 'supply-chain', name: 'Supply Chain Attack', category: 'ADVANCED' },
{ id: 'zero-day', name: 'Zero-Day Exploit', category: 'ADVANCED' }];

function inferBackendType(attack) {
  if (attack.backendType) return attack.backendType;
  if (attack.id === 'multi-vector') return null;
  if (attack.category === 'NETWORK') return 'ddos';
  if (attack.category === 'AUTH') return 'brute_force';
  if (attack.category === 'WEB') return 'sql_injection';
  if (attack.category === 'MALWARE') return 'multi_stage';
  return 'insider';
}

export const ATTACKS = RAW_ATTACKS.map((attack) => ({
  ...attack,
  active: true,
  backendType: inferBackendType(attack)
}));