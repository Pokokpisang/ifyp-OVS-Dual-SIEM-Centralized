/* eslint-disable */
// Mock data for OVS SOC

const NOW = new Date('2026-05-21T14:32:00Z');

const CLIENTS = [
  { id: 'c-001', name: 'Northwind Cloud', org: 'Hosting Provider', contact: 'Mei Tanaka', agents: 42, online: 38, offline: 3, silent: 1, alerts: 7, risk: 'high', status: 'active', lastActivity: '2m ago', country: 'JP' },
  { id: 'c-002', name: 'Stratus Partners', org: 'MSP', contact: 'Daniel Okafor', agents: 28, online: 26, offline: 2, silent: 0, alerts: 2, risk: 'medium', status: 'active', lastActivity: '11m ago', country: 'NG' },
  { id: 'c-003', name: 'Halcyon Labs', org: 'SaaS', contact: 'Priya Iyer', agents: 18, online: 16, offline: 1, silent: 1, alerts: 12, risk: 'critical', status: 'active', lastActivity: '1m ago', country: 'IN' },
  { id: 'c-004', name: 'Bluepine Hosting', org: 'Hosting Provider', contact: 'Marcus Reed', agents: 56, online: 55, offline: 1, silent: 0, alerts: 1, risk: 'low', status: 'active', lastActivity: '4m ago', country: 'CA' },
  { id: 'c-005', name: 'Polaris Systems', org: 'MSP', contact: 'Yuki Nakamura', agents: 14, online: 12, offline: 1, silent: 1, alerts: 3, risk: 'medium', status: 'active', lastActivity: '8m ago', country: 'JP' },
  { id: 'c-006', name: 'Verdant Stack', org: 'SaaS', contact: 'Sofía Romero', agents: 9, online: 9, offline: 0, silent: 0, alerts: 0, risk: 'low', status: 'trial', lastActivity: '2h ago', country: 'MX' },
  { id: 'c-007', name: 'Ironcove Servers', org: 'Hosting Provider', contact: 'James Whittaker', agents: 32, online: 30, offline: 2, silent: 0, alerts: 4, risk: 'medium', status: 'active', lastActivity: '6m ago', country: 'GB' },
  { id: 'c-008', name: 'Lattice Co-op', org: 'MSP', contact: 'Ada Bergström', agents: 7, online: 6, offline: 1, silent: 0, alerts: 0, risk: 'low', status: 'suspended', lastActivity: '3d ago', country: 'SE' },
  { id: 'c-009', name: 'Meridian Hosts', org: 'Hosting Provider', contact: 'Wei Chen', agents: 24, online: 23, offline: 1, silent: 0, alerts: 1, risk: 'low', status: 'active', lastActivity: '14m ago', country: 'SG' },
  { id: 'c-010', name: 'Quantra Tech', org: 'SaaS', contact: 'Liam Schofield', agents: 11, online: 9, offline: 1, silent: 1, alerts: 2, risk: 'medium', status: 'trial', lastActivity: '22m ago', country: 'AU' },
];

const ALERTS = [
  { id: 'A-7842', sev: 'critical', title: 'Suspicious sudo escalation chain detected', mitre: 'T1548.003', technique: 'Sudo Caching', agent: 'web-prod-04', client: 'Halcyon Labs', engine: 'YARA + Behavioral', status: 'open', risk: 92, ts: '2026-05-21T14:30:00Z' },
  { id: 'A-7841', sev: 'critical', title: 'Outbound C2 beacon to known TA-410 infrastructure', mitre: 'T1071.001', technique: 'Web Protocols', agent: 'app-srv-12', client: 'Halcyon Labs', engine: 'Network IOC', status: 'investigating', risk: 95, ts: '2026-05-21T14:24:00Z' },
  { id: 'A-7840', sev: 'high', title: 'Unusual cron job created with reverse shell pattern', mitre: 'T1053.003', technique: 'Cron', agent: 'db-replica-01', client: 'Northwind Cloud', engine: 'YAML Rule', status: 'investigating', risk: 78, ts: '2026-05-21T14:11:00Z' },
  { id: 'A-7839', sev: 'high', title: 'SSH brute force from rotating IP block (12 unique)', mitre: 'T1110.001', technique: 'Password Guessing', agent: 'edge-02', client: 'Bluepine Hosting', engine: 'Behavioral', status: 'open', risk: 71, ts: '2026-05-21T14:02:00Z' },
  { id: 'A-7838', sev: 'medium', title: 'New SUID binary deployed to /usr/local/bin', mitre: 'T1548.001', technique: 'Setuid and Setgid', agent: 'app-srv-04', client: 'Stratus Partners', engine: 'File Integrity', status: 'open', risk: 56, ts: '2026-05-21T13:48:00Z' },
  { id: 'A-7837', sev: 'high', title: 'Privileged user logged in from new geo (CN → EE)', mitre: 'T1078.003', technique: 'Local Accounts', agent: 'jump-prod-01', client: 'Northwind Cloud', engine: 'AI Triage', status: 'investigating', risk: 73, ts: '2026-05-21T13:31:00Z' },
  { id: 'A-7836', sev: 'medium', title: 'Auditd: kernel module load from non-standard path', mitre: 'T1547.006', technique: 'Kernel Modules', agent: 'web-prod-09', client: 'Ironcove Servers', engine: 'YAML Rule', status: 'investigating', risk: 60, ts: '2026-05-21T13:14:00Z' },
  { id: 'A-7835', sev: 'low', title: 'Sustained outbound DNS query volume from agent', mitre: 'T1071.004', technique: 'DNS', agent: 'mail-01', client: 'Polaris Systems', engine: 'Network', status: 'resolved', risk: 32, ts: '2026-05-21T12:50:00Z' },
  { id: 'A-7834', sev: 'low', title: 'Agent reported clock drift > 60s', mitre: '—', technique: '—', agent: 'db-replica-03', client: 'Quantra Tech', engine: 'Heartbeat', status: 'resolved', risk: 18, ts: '2026-05-21T12:32:00Z' },
  { id: 'A-7833', sev: 'medium', title: 'Process masquerading as systemd-journald', mitre: 'T1036.005', technique: 'Match Legitimate Name', agent: 'app-srv-02', client: 'Northwind Cloud', engine: 'Behavioral', status: 'open', risk: 54, ts: '2026-05-21T12:18:00Z' },
  { id: 'A-7832', sev: 'critical', title: 'Container escape attempt via runc CVE-2024-21626', mitre: 'T1611', technique: 'Container Escape', agent: 'k8s-node-07', client: 'Halcyon Labs', engine: 'YARA + Behavioral', status: 'open', risk: 96, ts: '2026-05-21T12:02:00Z' },
  { id: 'A-7831', sev: 'low', title: 'Package manager invoked outside maintenance window', mitre: 'T1072', technique: 'Software Deployment', agent: 'web-prod-04', client: 'Halcyon Labs', engine: 'Policy', status: 'false positive', risk: 22, ts: '2026-05-21T11:38:00Z' },
  { id: 'A-7830', sev: 'medium', title: 'Failed login burst from internal subnet', mitre: 'T1110.003', technique: 'Password Spraying', agent: 'auth-01', client: 'Ironcove Servers', engine: 'Behavioral', status: 'investigating', risk: 58, ts: '2026-05-21T11:11:00Z' },
];

const AGENTS = [
  { id: 'ag-001', name: 'web-prod-04', host: 'web-prod-04.hal.lab', ip: '10.42.7.4', client: 'Halcyon Labs', os: 'Ubuntu 22.04', version: '0.18.2', lastSeen: '12s', status: 'critical', ingest: 1240, cpu: 62, ram: 71, alerts: 4, key: 'rotated 12d' },
  { id: 'ag-002', name: 'app-srv-12', host: 'app-srv-12.hal.lab', ip: '10.42.7.12', client: 'Halcyon Labs', os: 'Debian 12', version: '0.18.2', lastSeen: '8s', status: 'critical', ingest: 980, cpu: 44, ram: 58, alerts: 3, key: 'rotated 6d' },
  { id: 'ag-003', name: 'db-replica-01', host: 'db-replica-01.nw.cloud', ip: '10.31.1.10', client: 'Northwind Cloud', os: 'AlmaLinux 9', version: '0.18.1', lastSeen: '34s', status: 'online', ingest: 720, cpu: 28, ram: 41, alerts: 1, key: 'rotated 2d' },
  { id: 'ag-004', name: 'edge-02', host: 'edge-02.bluepine.io', ip: '203.0.113.18', client: 'Bluepine Hosting', os: 'Ubuntu 24.04', version: '0.18.2', lastSeen: '5s', status: 'online', ingest: 1620, cpu: 71, ram: 64, alerts: 1, key: 'rotated 1d' },
  { id: 'ag-005', name: 'app-srv-04', host: 'app-srv-04.stratus.io', ip: '10.18.2.4', client: 'Stratus Partners', os: 'Debian 12', version: '0.17.9', lastSeen: '2m', status: 'silent', ingest: 0, cpu: 0, ram: 0, alerts: 1, key: 'rotated 28d' },
  { id: 'ag-006', name: 'jump-prod-01', host: 'jump-prod-01.nw.cloud', ip: '10.31.0.5', client: 'Northwind Cloud', os: 'Rocky 9', version: '0.18.2', lastSeen: '4s', status: 'online', ingest: 412, cpu: 16, ram: 32, alerts: 1, key: 'rotated 4d' },
  { id: 'ag-007', name: 'k8s-node-07', host: 'k8s-node-07.hal.lab', ip: '10.42.9.7', client: 'Halcyon Labs', os: 'Talos Linux', version: '0.18.2', lastSeen: '9s', status: 'critical', ingest: 2140, cpu: 81, ram: 79, alerts: 2, key: 'rotated 1d' },
  { id: 'ag-008', name: 'mail-01', host: 'mail-01.polaris.jp', ip: '10.55.3.10', client: 'Polaris Systems', os: 'Ubuntu 22.04', version: '0.18.1', lastSeen: '17s', status: 'online', ingest: 540, cpu: 22, ram: 39, alerts: 0, key: 'rotated 9d' },
  { id: 'ag-009', name: 'auth-01', host: 'auth-01.ironcove.uk', ip: '10.62.0.10', client: 'Ironcove Servers', os: 'Debian 12', version: '0.18.2', lastSeen: '11s', status: 'online', ingest: 380, cpu: 19, ram: 28, alerts: 1, key: 'rotated 14d' },
  { id: 'ag-010', name: 'web-prod-09', host: 'web-prod-09.ironcove.uk', ip: '10.62.7.9', client: 'Ironcove Servers', os: 'Ubuntu 22.04', version: '0.18.2', lastSeen: '5s', status: 'online', ingest: 920, cpu: 38, ram: 47, alerts: 1, key: 'rotated 7d' },
  { id: 'ag-011', name: 'db-replica-03', host: 'db-replica-03.quantra.au', ip: '10.71.1.13', client: 'Quantra Tech', os: 'Ubuntu 22.04', version: '0.18.0', lastSeen: '2m', status: 'silent', ingest: 0, cpu: 0, ram: 0, alerts: 1, key: 'rotated 33d' },
  { id: 'ag-012', name: 'edge-04', host: 'edge-04.bluepine.io', ip: '203.0.113.24', client: 'Bluepine Hosting', os: 'Ubuntu 24.04', version: '0.18.2', lastSeen: '7s', status: 'online', ingest: 1480, cpu: 58, ram: 55, alerts: 0, key: 'rotated 3d' },
  { id: 'ag-013', name: 'app-srv-02', host: 'app-srv-02.nw.cloud', ip: '10.31.2.2', client: 'Northwind Cloud', os: 'Debian 12', version: '0.18.2', lastSeen: '11s', status: 'online', ingest: 660, cpu: 31, ram: 44, alerts: 1, key: 'rotated 5d' },
  { id: 'ag-014', name: 'cache-01', host: 'cache-01.verdant.mx', ip: '10.81.1.1', client: 'Verdant Stack', os: 'Ubuntu 24.04', version: '0.18.2', lastSeen: '6s', status: 'online', ingest: 240, cpu: 11, ram: 23, alerts: 0, key: 'rotated 1d' },
  { id: 'ag-015', name: 'worker-02', host: 'worker-02.meridian.sg', ip: '10.91.0.2', client: 'Meridian Hosts', os: 'Debian 12', version: '0.18.1', lastSeen: '9s', status: 'online', ingest: 420, cpu: 24, ram: 36, alerts: 0, key: 'rotated 11d' },
];

const RULES = [
  { id: 'R-0182', name: 'Reverse shell via /dev/tcp', mitre: 'T1059.004', sev: 'critical', enabled: true, updated: '3d ago', fp: '1 in 30d', quality: 96, test: 'pass' },
  { id: 'R-0181', name: 'Tampering with auditd config', mitre: 'T1562.006', sev: 'high', enabled: true, updated: '7d ago', fp: '0', quality: 92, test: 'pass' },
  { id: 'R-0180', name: 'Kernel module loaded from /tmp', mitre: 'T1547.006', sev: 'high', enabled: true, updated: '1d ago', fp: '2 in 30d', quality: 88, test: 'pass' },
  { id: 'R-0179', name: 'Cron job created with curl|sh pattern', mitre: 'T1053.003', sev: 'high', enabled: true, updated: '5d ago', fp: '1 in 30d', quality: 90, test: 'pass' },
  { id: 'R-0178', name: 'Sudo cache abuse via tty hijack', mitre: 'T1548.003', sev: 'critical', enabled: true, updated: '12h ago', fp: '0', quality: 94, test: 'pass' },
  { id: 'R-0177', name: 'New SUID binary outside package manager', mitre: 'T1548.001', sev: 'medium', enabled: true, updated: '14d ago', fp: '4 in 30d', quality: 78, test: 'pass' },
  { id: 'R-0176', name: 'DNS exfiltration high-entropy subdomains', mitre: 'T1071.004', sev: 'high', enabled: true, updated: '2d ago', fp: '0', quality: 89, test: 'pass' },
  { id: 'R-0175', name: 'Container escape via runc symlink', mitre: 'T1611', sev: 'critical', enabled: true, updated: '8h ago', fp: '0', quality: 97, test: 'pass' },
  { id: 'R-0174', name: 'SSH brute force from rotating sources', mitre: 'T1110.001', sev: 'medium', enabled: true, updated: '6d ago', fp: '6 in 30d', quality: 71, test: 'pass' },
  { id: 'R-0173', name: 'Process masquerading as kernel thread', mitre: 'T1036.005', sev: 'high', enabled: true, updated: '4d ago', fp: '1 in 30d', quality: 86, test: 'pass' },
  { id: 'R-0172', name: 'Privileged login from new geographic region', mitre: 'T1078.003', sev: 'high', enabled: false, updated: '21d ago', fp: '12 in 30d', quality: 62, test: 'tuning' },
  { id: 'R-0171', name: 'Package install outside maintenance window', mitre: 'T1072', sev: 'low', enabled: true, updated: '15d ago', fp: '2 in 30d', quality: 74, test: 'pass' },
];

const SOAR_PLAYBOOKS = [
  { id: 'PB-01', name: 'Isolate compromised host', trigger: 'critical + lateral movement', steps: 6, mode: 'approval', runs: 12, success: 11 },
  { id: 'PB-02', name: 'Block egress C2 destination', trigger: 'outbound IOC match', steps: 4, mode: 'auto', runs: 38, success: 38 },
  { id: 'PB-03', name: 'Quarantine SUID binary', trigger: 'T1548.001 match', steps: 5, mode: 'approval', runs: 7, success: 6 },
  { id: 'PB-04', name: 'Rotate SSH keys after brute force', trigger: 'T1110.* > threshold', steps: 8, mode: 'approval', runs: 3, success: 3 },
  { id: 'PB-05', name: 'Snapshot evidence + freeze logs', trigger: 'manual', steps: 3, mode: 'auto', runs: 22, success: 22 },
  { id: 'PB-06', name: 'Notify on-call analyst', trigger: 'severity >= high', steps: 2, mode: 'auto', runs: 124, success: 122 },
];

const SOAR_QUEUE = [
  { id: 'EX-2204', playbook: 'Isolate compromised host', alert: 'A-7841', client: 'Halcyon Labs', agent: 'app-srv-12', status: 'pending', requested: '4m ago', requestedBy: 'AI Triage', risk: 95 },
  { id: 'EX-2203', playbook: 'Quarantine SUID binary', alert: 'A-7838', client: 'Stratus Partners', agent: 'app-srv-04', status: 'pending', requested: '12m ago', requestedBy: 'analyst:reed', risk: 56 },
  { id: 'EX-2202', playbook: 'Block egress C2 destination', alert: 'A-7841', client: 'Halcyon Labs', agent: 'app-srv-12', status: 'executed', requested: '24m ago', requestedBy: 'auto', risk: 95 },
  { id: 'EX-2201', playbook: 'Notify on-call analyst', alert: 'A-7842', client: 'Halcyon Labs', agent: 'web-prod-04', status: 'executed', requested: '38m ago', requestedBy: 'auto', risk: 92 },
  { id: 'EX-2200', playbook: 'Rotate SSH keys', alert: 'A-7839', client: 'Bluepine Hosting', agent: 'edge-02', status: 'rejected', requested: '1h ago', requestedBy: 'analyst:tanaka', risk: 71 },
  { id: 'EX-2199', playbook: 'Isolate compromised host', alert: 'A-7836', client: 'Ironcove Servers', agent: 'web-prod-09', status: 'failed', requested: '2h ago', requestedBy: 'AI Triage', risk: 60 },
];

const NETWORK_FLOWS = [
  { src: '10.42.7.12', dst: '185.225.74.84', port: 443, proto: 'TCP', bytes: '12.4 MB', pkts: 8912, score: 92, geo: 'RU', tag: 'C2 match' },
  { src: '10.42.9.7', dst: '94.102.61.7', port: 8443, proto: 'TCP', bytes: '2.1 MB', pkts: 1442, score: 88, geo: 'NL', tag: 'TOR exit' },
  { src: '10.55.3.10', dst: '8.8.8.8', port: 53, proto: 'UDP', bytes: '942 KB', pkts: 11240, score: 64, geo: 'US', tag: 'DNS burst' },
  { src: '10.31.1.10', dst: '52.84.124.12', port: 443, proto: 'TCP', bytes: '8.8 MB', pkts: 6240, score: 22, geo: 'US', tag: 'AWS' },
  { src: '10.62.7.9', dst: '192.0.2.18', port: 22, proto: 'TCP', bytes: '120 KB', pkts: 800, score: 71, geo: 'CN', tag: 'SSH unusual' },
  { src: '10.42.7.4', dst: '203.0.113.99', port: 4444, proto: 'TCP', bytes: '40 KB', pkts: 220, score: 96, geo: 'UA', tag: 'rev shell' },
];

const NOTIFICATIONS = [
  { id: 'N-9001', channel: 'PagerDuty', target: 'oncall-primary', delivered: true, ts: '2m ago', alert: 'A-7842' },
  { id: 'N-9000', channel: 'Slack', target: '#soc-critical', delivered: true, ts: '2m ago', alert: 'A-7842' },
  { id: 'N-8999', channel: 'Email', target: 'soc@northwind.cloud', delivered: true, ts: '11m ago', alert: 'A-7840' },
  { id: 'N-8998', channel: 'Webhook', target: 'hal-internal-bus', delivered: false, ts: '12m ago', alert: 'A-7841' },
  { id: 'N-8997', channel: 'Slack', target: '#bluepine-alerts', delivered: true, ts: '18m ago', alert: 'A-7839' },
  { id: 'N-8996', channel: 'SMS', target: '+44 *** 5512', delivered: true, ts: '1h ago', alert: 'A-7836' },
];

// Mini sparkline data
const SPARK = {
  alerts: [3, 5, 4, 7, 6, 9, 8, 12, 10, 8, 11, 14, 13, 16, 14],
  ingest: [820, 900, 1100, 1240, 1180, 1320, 1280, 1420, 1380, 1500, 1480, 1620, 1540, 1700, 1680],
  agents: [110, 112, 115, 119, 122, 125, 128, 130, 134, 138, 141, 144, 148, 152, 155],
  posture: [70, 72, 71, 73, 74, 72, 71, 70, 69, 67, 66, 64, 65, 63, 62],
};

// Recent timeline for hero alert
const EVIDENCE = [
  { t: '14:30:12', desc: 'Process /usr/bin/sudo spawned with TTY hijack pattern', sev: 'crit', tag: 'process' },
  { t: '14:29:58', desc: 'User pgw escalated to UID 0 via sudo cache (sudo_caching=on)', sev: 'crit', tag: 'auth' },
  { t: '14:29:51', desc: 'New file /var/spool/cron/crontabs/pgw with curl|sh pattern', sev: 'high', tag: 'file' },
  { t: '14:28:33', desc: 'Outbound TCP 203.0.113.99:4444 from PID 18422', sev: 'high', tag: 'network' },
  { t: '14:26:14', desc: 'TTY interactive session opened from 192.0.2.18 (CN → EE jump)', sev: 'info', tag: 'auth' },
  { t: '14:24:02', desc: 'AI triage scored event chain 92/100 — recommended containment', sev: 'info', tag: 'ai' },
  { t: '14:18:11', desc: 'Failed sudo attempts × 3 from pgw within 90s', sev: 'info', tag: 'auth' },
];

// 14×6 MITRE coverage grid
const MITRE_GRID = Array.from({length: 14 * 6}).map((_, i) => {
  const seed = (i * 9301 + 49297) % 233280;
  const r = seed / 233280;
  if (r < 0.18) return 0;
  if (r < 0.4) return 1;
  if (r < 0.65) return 2;
  if (r < 0.85) return 3;
  if (r < 0.96) return 4;
  return 5;
});

const MITRE_TACTICS = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Esc.',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command & Control', 'Exfiltration', 'Impact', 'Resource Dev.'
];

// Agent map 120 cells
const AGENT_MAP = Array.from({length: 240}).map((_, i) => {
  const seed = (i * 16807) % 2147483647;
  const r = seed / 2147483647;
  if (r < 0.04) return 'crit';
  if (r < 0.10) return 'silent';
  if (r < 0.16) return 'offline';
  return 'online';
});

// Traffic trend hourly
const TRAFFIC_INBOUND  = [620, 640, 580, 600, 720, 810, 920, 1040, 1120, 1180, 1240, 1260, 1280, 1340, 1380, 1420, 1480, 1520, 1560, 1610, 1640, 1660, 1700, 1720];
const TRAFFIC_OUTBOUND = [410, 420, 380, 400, 480, 560, 640, 720, 780, 820, 880, 920, 940, 980, 1020, 1080, 1120, 1180, 1220, 1280, 1320, 1380, 1420, 1460];
const TRAFFIC_BLOCKED  = [12, 8, 4, 6, 18, 22, 14, 32, 28, 18, 22, 34, 28, 42, 38, 24, 32, 28, 38, 44, 36, 28, 42, 52];

// Hours labels for 24h chart
const HOURS_24 = Array.from({length: 24}).map((_, i) => `${String(i).padStart(2,'0')}:00`).filter((_, i) => i % 4 === 0);

// =============================================================
// AUDIT TRAIL — read-only platform activity records
// details: ordered [key, value] pairs; value === '__SENSITIVE__' is
// rendered as a "Sensitive value hidden" chip (never a real secret).
// related: { label, page }  page = a nav route id, or null (no target)
// =============================================================
const AUDIT_EVENTS = [
  { id: 'ev-10241', ts: '2026-07-03 10:21:44', actor: 'analyst01', actorRole: 'Senior Analyst', action: 'SOAR_APPROVE', category: 'SOAR', objType: 'soar_execution', objId: '91', result: 'Approved', source: '10.10.4.21',
    details: [['alert_id', '42'], ['playbook_id', 't1543_systemd_persistence_review'], ['decision', 'approved'], ['approver', 'analyst01']],
    related: [{ label: 'Open SOAR History', page: 'soar-history' }, { label: 'Open Alert Investigation', page: 'investigation' }] },
  { id: 'ev-10240', ts: '2026-07-03 10:18:11', actor: 'admin', actorRole: 'SOC Lead', action: 'ALERT_STATUS_CHANGED', category: 'Alert', objType: 'alert', objId: '42', result: 'Updated', source: '10.10.0.5',
    details: [['from', 'open'], ['to', 'resolved'], ['note_present', 'true']],
    related: [{ label: 'Open Alert Investigation', page: 'investigation' }] },
  { id: 'ev-10239', ts: '2026-07-03 10:10:05', actor: 'system:auto', actorRole: 'Automation', action: 'SOAR_RUN', category: 'SOAR', objType: 'soar_execution', objId: '90', result: 'Executed', source: 'system',
    details: [['alert_id', '40'], ['playbook_id', 't1110_ssh_bruteforce_block'], ['trigger', 'rule:auto'], ['steps', '4/4 ok']],
    related: [{ label: 'Open SOAR History', page: 'soar-history' }] },
  { id: 'ev-10238', ts: '2026-07-03 09:55:31', actor: 'admin', actorRole: 'SOC Lead', action: 'AGENT_KEY_ROTATED', category: 'Agent', objType: 'agent', objId: '7', result: 'Rotated', source: '10.10.0.5', sensitive: true,
    details: [['hostname', 'ovs-agent-01'], ['reason', 'reinstall token generated'], ['key_visible', 'false'], ['new_key', '__SENSITIVE__']],
    related: [{ label: 'Open Agent', page: 'agents' }] },
  { id: 'ev-10237', ts: '2026-07-03 09:50:02', actor: 'firdaus', actorRole: 'Client Admin', action: 'LOGIN_FAILURE', category: 'Authentication', objType: 'auth', objId: null, result: 'Failed', source: '203.0.113.77',
    details: [['method', 'password'], ['reason', 'invalid_credentials'], ['attempt', '3 of 5'], ['user_agent', 'Firefox/126 · Linux']],
    related: [{ label: 'Open Login Context', page: null }] },
  { id: 'ev-10236', ts: '2026-07-03 09:45:22', actor: 'analyst02', actorRole: 'Junior Analyst', action: 'AI_TRIAGE_REQUESTED', category: 'AI Triage', objType: 'ai_triage', objId: '39', result: 'Queued', source: '10.10.4.22',
    details: [['alert_id', '39'], ['model', 'ovs-triage-mini v0.4.2'], ['priority', 'high'], ['prompt_stored', 'false']],
    related: [{ label: 'Open AI Triage Result', page: 'ai' }, { label: 'Open Alert Investigation', page: 'investigation' }] },
  { id: 'ev-10235', ts: '2026-07-03 09:31:10', actor: 'analyst02', actorRole: 'Junior Analyst', action: 'LOGIN_SUCCESS', category: 'Authentication', objType: 'auth', objId: null, result: 'Success', source: '10.10.4.22',
    details: [['method', 'sso'], ['provider', 'okta'], ['mfa', 'passed'], ['session', 's-8841c2']],
    related: [{ label: 'Open Login Context', page: null }] },
  { id: 'ev-10234', ts: '2026-07-03 09:12:48', actor: 'system:auto', actorRole: 'Automation', action: 'SOAR_RUN', category: 'SOAR', objType: 'soar_execution', objId: '89', result: 'Executed', source: 'system',
    details: [['alert_id', '38'], ['playbook_id', 't1071_c2_beacon_isolate'], ['trigger', 'rule:auto'], ['steps', '5/5 ok']],
    related: [{ label: 'Open SOAR History', page: 'soar-history' }] },
  { id: 'ev-10233', ts: '2026-07-03 08:58:33', actor: 'admin', actorRole: 'SOC Lead', action: 'SOAR_REJECT', category: 'SOAR', objType: 'soar_execution', objId: '88', result: 'Rejected', source: '10.10.0.5',
    details: [['alert_id', '37'], ['playbook_id', 't1548_host_isolation'], ['decision', 'rejected'], ['reason', 'scope too broad — narrowing manually']],
    related: [{ label: 'Open SOAR History', page: 'soar-history' }, { label: 'Open Alert Investigation', page: 'investigation' }] },
  { id: 'ev-10232', ts: '2026-07-03 08:40:19', actor: 'd.okafor', actorRole: 'Senior Analyst', action: 'ALERT_STATUS_CHANGED', category: 'Alert', objType: 'alert', objId: '37', result: 'Updated', source: '10.10.4.18',
    details: [['from', 'open'], ['to', 'investigating'], ['assigned_to', 'd.okafor'], ['note_present', 'true']],
    related: [{ label: 'Open Alert Investigation', page: 'investigation' }] },
  { id: 'ev-10231', ts: '2026-07-03 08:22:57', actor: 'system:auto', actorRole: 'Automation', action: 'AGENT_REGISTERED', category: 'Agent', objType: 'agent', objId: '214', result: 'Registered', source: 'system',
    details: [['hostname', 'app-srv-15.bluepine.io'], ['os', 'Ubuntu 24.04'], ['install_token', '__SENSITIVE__'], ['approved_by', 'auto-approve policy']],
    related: [{ label: 'Open Agent', page: 'agents' }] },
  { id: 'ev-10230', ts: '2026-07-03 08:05:41', actor: 'analyst01', actorRole: 'Senior Analyst', action: 'AI_TRIAGE_REQUESTED', category: 'AI Triage', objType: 'ai_triage', objId: '36', result: 'Queued', source: '10.10.4.21',
    details: [['alert_id', '36'], ['model', 'ovs-triage-mini v0.4.2'], ['priority', 'medium'], ['prompt_stored', 'false']],
    related: [{ label: 'Open AI Triage Result', page: 'ai' }] },
  { id: 'ev-10229', ts: '2026-07-03 07:49:02', actor: 'p.kareem', actorRole: 'SOC Lead', action: 'LOGIN_SUCCESS', category: 'Authentication', objType: 'auth', objId: null, result: 'Success', source: '10.10.0.5',
    details: [['method', 'sso'], ['provider', 'okta'], ['mfa', 'passed'], ['session', 's-8840a1']],
    related: [{ label: 'Open Login Context', page: null }] },
  { id: 'ev-10228', ts: '2026-07-03 07:30:15', actor: 'firdaus', actorRole: 'Client Admin', action: 'LOGIN_FAILURE', category: 'Authentication', objType: 'auth', objId: null, result: 'Failed', source: '203.0.113.77',
    details: [['method', 'password'], ['reason', 'invalid_credentials'], ['attempt', '2 of 5'], ['user_agent', 'Firefox/126 · Linux']],
    related: [{ label: 'Open Login Context', page: null }] },
  { id: 'ev-10227', ts: '2026-07-03 07:11:38', actor: 'firdaus', actorRole: 'Client Admin', action: 'LOGIN_FAILURE', category: 'Authentication', objType: 'auth', objId: null, result: 'Failed', source: '203.0.113.77',
    details: [['method', 'password'], ['reason', 'invalid_credentials'], ['attempt', '1 of 5'], ['user_agent', 'Firefox/126 · Linux']],
    related: [{ label: 'Open Login Context', page: null }] },
  { id: 'ev-10226', ts: '2026-07-03 06:58:20', actor: 'admin', actorRole: 'SOC Lead', action: 'SOAR_APPROVE', category: 'SOAR', objType: 'soar_execution', objId: '87', result: 'Approved', source: '10.10.0.5',
    details: [['alert_id', '35'], ['playbook_id', 't1053_cron_reverse_shell_kill'], ['decision', 'approved'], ['approver', 'admin']],
    related: [{ label: 'Open SOAR History', page: 'soar-history' }] },
  { id: 'ev-10225', ts: '2026-07-03 06:40:11', actor: 'admin', actorRole: 'SOC Lead', action: 'SYSTEM_CONFIG_CHANGED', category: 'System', objType: 'system', objId: null, result: 'Updated', source: '10.10.0.5',
    details: [['setting', 'retention.raw_log'], ['from', '90 days'], ['to', '180 days'], ['scope', 'workspace']],
    related: [{ label: 'Open Settings', page: 'settings' }] },
  { id: 'ev-10224', ts: '2026-07-03 06:22:03', actor: 'analyst02', actorRole: 'Junior Analyst', action: 'ALERT_STATUS_CHANGED', category: 'Alert', objType: 'alert', objId: '35', result: 'Updated', source: '10.10.4.22',
    details: [['from', 'investigating'], ['to', 'resolved'], ['note_present', 'true']],
    related: [{ label: 'Open Alert Investigation', page: 'investigation' }] },
  { id: 'ev-10223', ts: '2026-07-03 05:59:47', actor: 'system:auto', actorRole: 'Automation', action: 'AI_TRIAGE_COMPLETED', category: 'AI Triage', objType: 'ai_triage', objId: '34', result: 'Completed', source: 'system',
    details: [['alert_id', '34'], ['verdict', 'true_positive'], ['confidence', '0.92'], ['escalated', 'true']],
    related: [{ label: 'Open AI Triage Result', page: 'ai' }, { label: 'Open Alert Investigation', page: 'investigation' }] },
  { id: 'ev-10222', ts: '2026-07-02 23:41:12', actor: 'd.okafor', actorRole: 'Senior Analyst', action: 'LOGOUT', category: 'Authentication', objType: 'auth', objId: null, result: 'Success', source: '10.10.4.18',
    details: [['method', 'manual'], ['session', 's-8836d9'], ['duration', '4h 12m']],
    related: [{ label: 'Open Login Context', page: null }] },
  { id: 'ev-10221', ts: '2026-07-02 22:18:05', actor: 'admin', actorRole: 'SOC Lead', action: 'AGENT_KEY_ROTATED', category: 'Agent', objType: 'agent', objId: '5', result: 'Rotated', source: '10.10.0.5', sensitive: true,
    details: [['hostname', 'db-replica-01.nw.cloud'], ['reason', 'scheduled 14-day rotation'], ['key_visible', 'false'], ['new_key', '__SENSITIVE__']],
    related: [{ label: 'Open Agent', page: 'agents' }] },
  { id: 'ev-10220', ts: '2026-07-02 21:02:44', actor: 'system:auto', actorRole: 'Automation', action: 'SOAR_RUN', category: 'SOAR', objType: 'soar_execution', objId: '84', result: 'Executed', source: 'system',
    details: [['alert_id', '33'], ['playbook_id', 't1105_ioc_containment'], ['trigger', 'rule:auto'], ['steps', '3/3 ok']],
    related: [{ label: 'Open SOAR History', page: 'soar-history' }] },
  { id: 'ev-10219', ts: '2026-07-02 20:15:33', actor: 'analyst01', actorRole: 'Senior Analyst', action: 'SOAR_APPROVE', category: 'SOAR', objType: 'soar_execution', objId: '83', result: 'Approved', source: '10.10.4.21',
    details: [['alert_id', '32'], ['playbook_id', 't1078_disable_account'], ['decision', 'approved'], ['approver', 'analyst01']],
    related: [{ label: 'Open SOAR History', page: 'soar-history' }] },
  { id: 'ev-10218', ts: '2026-07-02 19:48:26', actor: 'admin', actorRole: 'SOC Lead', action: 'SYSTEM_CONFIG_CHANGED', category: 'System', objType: 'system', objId: null, result: 'Updated', source: '10.10.0.5',
    details: [['setting', 'auth.session_timeout'], ['from', '8 hours'], ['to', '4 hours'], ['scope', 'workspace']],
    related: [{ label: 'Open Settings', page: 'settings' }] },
  { id: 'ev-10217', ts: '2026-07-02 18:33:19', actor: 'j.whittaker', actorRole: 'Client Viewer', action: 'LOGIN_FAILURE', category: 'Authentication', objType: 'auth', objId: null, result: 'Failed', source: '198.51.100.44',
    details: [['method', 'password'], ['reason', 'mfa_required'], ['attempt', '1 of 5'], ['user_agent', 'Safari/17 · macOS']],
    related: [{ label: 'Open Login Context', page: null }] },
  { id: 'ev-10216', ts: '2026-07-02 17:20:08', actor: 'analyst02', actorRole: 'Junior Analyst', action: 'AI_TRIAGE_REQUESTED', category: 'AI Triage', objType: 'ai_triage', objId: '31', result: 'Queued', source: '10.10.4.22',
    details: [['alert_id', '31'], ['model', 'ovs-triage-mini v0.4.2'], ['priority', 'low'], ['prompt_stored', 'false']],
    related: [{ label: 'Open AI Triage Result', page: 'ai' }] },
  { id: 'ev-10215', ts: '2026-07-02 16:05:52', actor: 'admin', actorRole: 'SOC Lead', action: 'ALERT_STATUS_CHANGED', category: 'Alert', objType: 'alert', objId: '30', result: 'Updated', source: '10.10.0.5',
    details: [['from', 'open'], ['to', 'false_positive'], ['note_present', 'true']],
    related: [{ label: 'Open Alert Investigation', page: 'investigation' }] },
  { id: 'ev-10214', ts: '2026-07-02 15:44:37', actor: 'system:auto', actorRole: 'Automation', action: 'AGENT_DEREGISTERED', category: 'Agent', objType: 'agent', objId: '198', result: 'Removed', source: 'system',
    details: [['hostname', 'legacy-web-03.lattice.coop'], ['reason', 'no heartbeat 30 days'], ['data_retained', 'true']],
    related: [{ label: 'Open Agent', page: 'agents' }] },
];

Object.assign(window, {
  CLIENTS, ALERTS, AGENTS, RULES, SOAR_PLAYBOOKS, SOAR_QUEUE,
  NETWORK_FLOWS, NOTIFICATIONS, SPARK, EVIDENCE, MITRE_GRID, MITRE_TACTICS, AGENT_MAP,
  TRAFFIC_INBOUND, TRAFFIC_OUTBOUND, TRAFFIC_BLOCKED, HOURS_24, NOW, AUDIT_EVENTS,
});
