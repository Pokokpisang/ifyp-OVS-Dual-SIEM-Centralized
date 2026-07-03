/* eslint-disable */
// Icons + shared components for OVS SOC

const { useState: useStateShared, useEffect: useEffectShared, useRef: useRefShared } = React;

const Icon = ({ name, size = 16, stroke = 1.6 }) => {
  const paths = {
    overview: <><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></>,
    alert: <><path d="M12 9v4M12 17h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/></>,
    investigate: <><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3M11 8v3l2 1"/></>,
    agent: <><rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 22h8M12 18v4"/><circle cx="7" cy="11" r="1.2" fill="currentColor" stroke="none"/></>,
    network: <><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v3M10.5 11 6 17M13.5 11 18 17"/></>,
    rule: <><path d="M4 4h13l3 3v13H4z"/><path d="M8 8h8M8 12h8M8 16h5"/></>,
    ai: <><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1"/><circle cx="12" cy="12" r="3.5"/></>,
    soar: <><path d="M13 2 4 14h7l-1 8 9-12h-7z" /></>,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/></>,
    clients: <><circle cx="9" cy="8" r="3.5"/><circle cx="17" cy="9" r="2.5"/><path d="M2.5 20c0-3.5 2.9-6 6.5-6s6.5 2.5 6.5 6M16 20c0-2.6 1.5-4.5 4-5"/></>,
    reports: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h4"/></>,
    bell: <><path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h0a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></>,
    rbac: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="M9 12l2 2 4-4"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></>,
    menu: <><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></>,
    plus: <><path d="M12 5v14M5 12h14"/></>,
    download: <><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></>,
    upload: <><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/></>,
    chevron: <><path d="m9 18 6-6-6-6"/></>,
    chevronDown: <><path d="m6 9 6 6 6-6"/></>,
    x: <><path d="M18 6 6 18M6 6l18 18" transform="scale(0.75) translate(2,2)"/></>,
    filter: <><path d="M22 3H2l8 9.46V19l4 2v-8.54z"/></>,
    refresh: <><path d="M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5M21 12a9 9 0 0 1-15 6.7L3 16M3 21v-5h5"/></>,
    check: <><path d="M5 13l4 4L19 7"/></>,
    flag: <><path d="M4 21V4M4 4h14l-3 5 3 5H4"/></>,
    play: <><path d="M5 3l14 9-14 9z"/></>,
    pause: <><path d="M6 4h4v16H6zM14 4h4v16h-4z"/></>,
    user: <><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-7 8-7s8 3 8 7"/></>,
    shield: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></>,
    cpu: <><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></>,
    activity: <><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></>,
    trend: <><path d="M3 17l6-6 4 4 8-8M14 7h7v7"/></>,
    eye: <><path d="M2 12s4-8 10-8 10 8 10 8-4 8-10 8-10-8-10-8z"/><circle cx="12" cy="12" r="3"/></>,
    key: <><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></>,
    map: <><path d="M3 6l6-2 6 2 6-2v14l-6 2-6-2-6 2zM9 4v16M15 6v16"/></>,
    grid: <><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></>,
    sliders: <><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></>,
    book: <><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2zM22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></>,
    help: <><circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01"/></>,
    logout: <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></>,
    file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></>,
    spinner: <><path d="M21 12a9 9 0 1 1-6.2-8.5"/></>,
    link: <><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7L11.5 6"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7L12.5 18"/></>,
    code: <><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></>,
    bug: <><rect x="8" y="6" width="8" height="14" rx="4"/><path d="M2 12h6M16 12h6M12 2v4M5 4l3 3M19 4l-3 3M3 20l5-3M21 20l-5-3"/></>,
    folder: <><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></>,
    edit: <><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></>,
    moreVertical: <><circle cx="12" cy="5" r="1.5" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="12" cy="19" r="1.5" fill="currentColor" stroke="none"/></>,
    moreHorizontal: <><circle cx="5" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1.5" fill="currentColor" stroke="none"/></>,
    arrowUp: <><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></>,
    arrowDown: <><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></>,
    arrowRight: <><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></>,
    flame: <><path d="M8 14s1-7 6-10c0 5 4 6 4 11a6 6 0 0 1-12 0c0-2 1-3 1-3s1 2 1 2z"/></>,
    globe: <><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/></>,
    zap: <><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></>,
    inbox: <><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"/></>,
    layers: <><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></>,
    server: <><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></>,
    headset: <><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1v-6h3zM3 19a2 2 0 0 0 2 2h1v-6H3z"/></>,
    pdf: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><text x="7" y="18" fontSize="6" fill="currentColor" stroke="none" fontFamily="monospace" fontWeight="700">PDF</text></>,
    csv: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><text x="7" y="18" fontSize="6" fill="currentColor" stroke="none" fontFamily="monospace" fontWeight="700">CSV</text></>,
    sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></>,
    moon: <><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></>,
    chat: <><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></>,
  };
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round">
      {paths[name] || null}
    </svg>
  );
};

// --- KPI (bare stat block — use inside a .kpi-row or .card wrapper, no card of its own) ---
const KPI = ({ label, value, unit, delta, deltaDir, sub, accent }) => (
  <div className="kpi">
    <div className="kpi-label">{label}</div>
    <div className="kpi-value tnum">
      <span style={{color: accent || 'inherit'}}>{value}</span>
      {unit && <span className="unit">{unit}</span>}
    </div>
    <div className="kpi-foot">
      {delta != null ? (
        <span className={`kpi-delta ${deltaDir === 'up' ? 'up' : 'down'}`}>
          <Icon name={deltaDir === 'up' ? 'arrowUp' : 'arrowDown'} size={10} />
          {delta}
        </span>
      ) : null}
      {sub && <span className="dim">{sub}</span>}
    </div>
  </div>
);

// --- Sparkline ---
const Sparkline = ({ data, color = '#F05484', width = 100, height = 30, fill = true }) => {
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const step = width / (data.length - 1);
  const points = data.map((d, i) => [i * step, height - ((d - min) / range) * (height - 4) - 2]);
  const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');
  const area = `${path} L ${width} ${height} L 0 ${height} Z`;
  return (
    <svg className="spark" width={width} height={height}>
      {fill && <path d={area} fill={color} opacity={0.14} />}
      <path d={path} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round"/>
      <circle cx={points[points.length-1][0]} cy={points[points.length-1][1]} r={2.2} fill={color}/>
    </svg>
  );
};

// --- Bar histogram ---
const BarHisto = ({ data, color = '#F05484', width = 240, height = 60, gap = 2 }) => {
  const max = Math.max(...data) || 1;
  const bw = (width - gap * (data.length - 1)) / data.length;
  return (
    <svg width={width} height={height}>
      {data.map((v, i) => {
        const h = (v / max) * (height - 4);
        return (
          <rect key={i}
            x={i * (bw + gap)} y={height - h}
            width={bw} height={h}
            fill={color} opacity={0.3 + 0.7 * (v / max)}
            rx={1}
          />
        );
      })}
    </svg>
  );
};

// --- Stacked area / line chart ---
const AreaChart = ({ series, width = 600, height = 200, labels = [] }) => {
  // series: [{name, color, data}]
  const all = series.flatMap(s => s.data);
  const max = Math.max(...all) * 1.15;
  const min = 0;
  const n = series[0].data.length;
  const step = width / (n - 1);
  const yScale = v => height - 24 - ((v - min) / (max - min)) * (height - 40);
  const gridLines = 4;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{display: 'block', width: '100%', height, maxWidth: width}}>
      {/* grid */}
      {Array.from({length: gridLines + 1}).map((_, i) => {
        const y = 12 + (i * (height - 36) / gridLines);
        return <line key={i} x1={0} x2={width} y1={y} y2={y} stroke="var(--grid-line)" />;
      })}
      {series.map((s, si) => {
        const pts = s.data.map((d, i) => [i * step, yScale(d)]);
        const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');
        const area = `${line} L ${width} ${height - 24} L 0 ${height - 24} Z`;
        return (
          <g key={si}>
            <path d={area} fill={s.color} opacity={0.1}/>
            <path d={line} fill="none" stroke={s.color} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" />
          </g>
        );
      })}
      {labels.map((l, i) => (
        <text key={i} x={i * (width / (labels.length - 1))} y={height - 6}
          fontSize={9.5} fill="var(--text-dim)" fontFamily="IBM Plex Mono"
          textAnchor={i === 0 ? 'start' : i === labels.length - 1 ? 'end' : 'middle'}>
          {l}
        </text>
      ))}
    </svg>
  );
};

// --- Donut ---
const Donut = ({ data, size = 130, thickness = 16, centerLabel, centerSub }) => {
  const total = data.reduce((s, d) => s + d.value, 0);
  let acc = 0;
  const r = size/2 - thickness/2;
  const c = 2 * Math.PI * r;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--bg-elev-2)" strokeWidth={thickness}/>
      {data.map((d, i) => {
        const frac = d.value / total;
        const dash = c * frac;
        const offset = c * (1 - acc);
        acc += frac;
        return (
          <circle key={i}
            cx={size/2} cy={size/2} r={r}
            fill="none"
            stroke={d.color}
            strokeWidth={thickness}
            strokeDasharray={`${dash} ${c - dash}`}
            strokeDashoffset={offset}
            transform={`rotate(-90 ${size/2} ${size/2})`}
            strokeLinecap="butt"
          />
        );
      })}
      {centerLabel && <text x="50%" y="48%" textAnchor="middle" fontSize="22" fontWeight="600" fill="var(--text)" fontFamily="IBM Plex Sans">{centerLabel}</text>}
      {centerSub && <text x="50%" y="64%" textAnchor="middle" fontSize="10" fill="var(--text-dim)" fontFamily="IBM Plex Mono" letterSpacing="0.1em">{centerSub}</text>}
    </svg>
  );
};

// --- Severity badge ---
const Sev = ({ level }) => {
  const cls = { critical: 'crit', high: 'high', medium: 'med', low: 'low' }[level] || 'muted';
  return <span className={`badge ${cls}`}>{level}</span>;
};

const Status = ({ s }) => {
  const map = {
    open: { c: 'crit', label: 'OPEN' },
    investigating: { c: 'high', label: 'INVESTIGATING' },
    resolved: { c: 'ok', label: 'RESOLVED' },
    'false positive': { c: 'muted', label: 'FALSE POSITIVE' },
    active: { c: 'ok', label: 'ACTIVE' },
    inactive: { c: 'muted', label: 'INACTIVE' },
    suspended: { c: 'high', label: 'SUSPENDED' },
    trial: { c: 'info', label: 'TRIAL' },
    online: { c: 'ok', label: 'ONLINE' },
    offline: { c: 'muted', label: 'OFFLINE' },
    silent: { c: 'high', label: 'SILENT' },
    pending: { c: 'high', label: 'PENDING' },
    approved: { c: 'ok', label: 'APPROVED' },
    rejected: { c: 'crit', label: 'REJECTED' },
    executed: { c: 'ok', label: 'EXECUTED' },
    failed: { c: 'crit', label: 'FAILED' },
    simulated: { c: 'info', label: 'SIMULATED' },
    enabled: { c: 'ok', label: 'ENABLED' },
    disabled: { c: 'muted', label: 'DISABLED' },
  }[s] || { c: 'muted', label: s };
  return <span className={`badge ${map.c}`}>{map.label}</span>;
};

// --- Section header w/ tabs ---
const Tabs = ({ tabs, value, onChange }) => (
  <div className="tabs">
    {tabs.map(t => (
      <button key={t.id} className={`tab ${value === t.id ? 'active' : ''}`} onClick={() => onChange(t.id)}>
        {t.label}{t.count != null && <span className="count">{t.count}</span>}
      </button>
    ))}
  </div>
);

// --- Toggle ---
const Toggle = ({ on, onChange }) => (
  <div className={`toggle ${on ? 'on' : ''}`} onClick={() => onChange(!on)}>
    <div className="knob"/>
  </div>
);

// --- Drawer ---
const Drawer = ({ open, onClose, children }) => {
  if (!open) return null;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose}/>
      <div className="drawer">{children}</div>
    </>
  );
};

// --- MITRE heatmap ---
const MitreHeatmap = ({ cells, onHover, compact }) => {
  // cells: 14x6 grid; values 0..5
  return (
    <div className="mitre-grid" style={{ gridTemplateColumns: `repeat(${compact ? 12 : 14}, 1fr)` }}>
      {cells.map((v, i) => {
        const a = v === 0 ? 0.08 : 0.15 + v * 0.17;
        const color = v === 0 ? 'var(--bg-elev-2)' :
          v >= 4 ? `rgba(255,77,109,${a + 0.2})` :
          v >= 3 ? `rgba(245,155,0,${a + 0.2})` :
          v >= 2 ? `rgba(240,84,132,${a + 0.2})` :
          `rgba(91,158,255,${a + 0.2})`;
        return (
          <div key={i} className="mitre-cell" style={{background: color}} title={`Technique ${i}`}/>
        );
      })}
    </div>
  );
};

// --- Helpers ---
const cn = (...c) => c.filter(Boolean).join(' ');

const fmt = (n) => {
  if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n/1000).toFixed(1) + 'K';
  return n.toString();
};

const timeAgo = (iso) => {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h/24)}d ago`;
};

// Risk meter — flat zoned bar with a single marker (no gradient)
const RiskMarker = ({ score, max = 100 }) => {
  const zoneColor = score >= 80 ? 'var(--crit)' : score >= 60 ? 'var(--high)' : score >= 40 ? 'var(--med)' : 'var(--ok)';
  return (
    <div>
      <div className="risk-marker">
        <div className="zone" style={{background: 'var(--ok-soft)'}}/>
        <div className="zone" style={{background: 'var(--med-soft)'}}/>
        <div className="zone" style={{background: 'var(--high-soft)'}}/>
        <div className="zone" style={{background: 'var(--crit-soft)'}}/>
        <div className="indicator" style={{left: `calc(${(score/max) * 100}% - 1px)`, background: zoneColor}}/>
      </div>
      <div style={{display: 'flex', justifyContent: 'space-between', marginTop: 5, fontFamily: 'IBM Plex Mono', fontSize: 9.5, color: 'var(--text-dim)', letterSpacing: '0.08em'}}>
        <span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span>
      </div>
    </div>
  );
};

// Page section wrapper
const Section = ({ title, action, children, sub }) => (
  <div className="col" style={{gap: 'var(--gap-2)'}}>
    {title && (
      <div className="section-h">
        <div>
          <h3>{title}</h3>
          {sub && <div className="card-sub" style={{marginTop: 2}}>{sub}</div>}
        </div>
        {action}
      </div>
    )}
    {children}
  </div>
);

// Empty state
const Empty = ({ icon = 'inbox', title, sub, action }) => (
  <div className="empty">
    <div style={{color: 'var(--text-dim)'}}>
      <Icon name={icon} size={28} stroke={1.2}/>
    </div>
    <div className="ttl">{title}</div>
    <div style={{fontSize: 12, marginBottom: 14}}>{sub}</div>
    {action}
  </div>
);

// Coverage gauge
const CoverageGauge = ({ pct, label }) => (
  <div className="row" style={{gap: 14}}>
    <div className="gauge" style={{'--p': pct}}>
      <div style={{display: 'flex', flexDirection: 'column', alignItems: 'center'}}>
        <div style={{fontSize: 22, fontWeight: 600, fontFamily: 'IBM Plex Sans'}}>{pct}<span style={{fontSize: 11, color: 'var(--text-dim)'}}>%</span></div>
        <div style={{fontSize: 9, fontFamily: 'IBM Plex Mono', color: 'var(--text-dim)', letterSpacing: '0.1em'}}>COVERAGE</div>
      </div>
    </div>
    <div className="col" style={{gap: 6}}>
      <div className="kpi-label">{label}</div>
      <div className="muted" style={{fontSize: 11.5}}>Tactics: <span className="mono" style={{color: 'var(--text)'}}>14/14</span></div>
      <div className="muted" style={{fontSize: 11.5}}>Techniques: <span className="mono" style={{color: 'var(--text)'}}>118/201</span></div>
      <div className="muted" style={{fontSize: 11.5}}>Active rules: <span className="mono" style={{color: 'var(--text)'}}>248</span></div>
    </div>
  </div>
);

// =============================================================
// Global toast system — fire-and-forget notifications for action
// buttons across every page. showToast() can be called from any
// script file; ToastHost (mounted once in app.jsx) renders the queue.
// =============================================================
const showToast = (message, type = 'info') => {
  window.dispatchEvent(new CustomEvent('ovs:toast', { detail: { message, type, id: Date.now() + Math.random() } }));
};

const ToastHost = () => {
  const [toasts, setToasts] = useStateShared([]);
  useEffectShared(() => {
    const handler = (e) => {
      const t = e.detail;
      setToasts(ts => [...ts, t]);
      setTimeout(() => setToasts(ts => ts.filter(x => x.id !== t.id)), 3400);
    };
    window.addEventListener('ovs:toast', handler);
    return () => window.removeEventListener('ovs:toast', handler);
  }, []);
  if (toasts.length === 0) return null;
  return (
    <div className="toast-host">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type}`}>
          <span style={{color: t.type === 'success' ? 'var(--ok)' : t.type === 'error' ? 'var(--crit)' : t.type === 'warn' ? 'var(--high)' : 'var(--primary)', display: 'flex'}}>
            <Icon name={t.type === 'success' ? 'check' : t.type === 'error' ? 'alert' : t.type === 'warn' ? 'flame' : 'zap'} size={14} stroke={2}/>
          </span>
          <span>{t.message}</span>
        </div>
      ))}
    </div>
  );
};

// =============================================================
// IconMenu — small themed dropdown for row-level "…" actions.
// items: [{ label, icon, onClick, danger }] or { divider: true }
// =============================================================
const IconMenu = ({ icon = 'moreHorizontal', items = [] }) => {
  const [open, setOpen] = useStateShared(false);
  const ref = useRefShared(null);
  useEffectShared(() => {
    if (!open) return;
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);
  return (
    <div className="icon-menu" ref={ref} onClick={e => e.stopPropagation()}>
      <button className="icon-btn" onClick={() => setOpen(o => !o)}><Icon name={icon} size={14}/></button>
      {open && (
        <div className="icon-menu-pop">
          {items.map((it, i) => it.divider ? (
            <div key={i} className="icon-menu-divider"/>
          ) : (
            <div key={i} className={`icon-menu-item ${it.danger ? 'danger' : ''}`} onClick={() => { setOpen(false); it.onClick?.(); }}>
              {it.icon && <Icon name={it.icon} size={13}/>}
              {it.label}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// =============================================================
// SimpleFormDrawer — generic "create/invite/deploy" panel reused by
// every "+ New X" button across the app so each doesn't need its own
// bespoke modal. fields: [{ label, type: 'text'|'select'|'textarea',
// options, placeholder, default }]
// =============================================================
const formFieldStyle = { background: 'var(--bg-elev)', border: '1px solid var(--border)', color: 'var(--text)', padding: '8px 12px', borderRadius: 6, fontSize: 12.5, fontFamily: 'IBM Plex Sans', outline: 'none', width: '100%' };

const SimpleFormDrawer = ({ title, subtitle, fields = [], submitLabel = 'Create', onClose, onSubmit }) => (
  <Drawer open={true} onClose={onClose}>
    <div className="drawer-header">
      <div>
        <div style={{fontSize: 17, fontWeight: 600}}>{title}</div>
        {subtitle && <div className="card-sub">{subtitle}</div>}
      </div>
      <button className="icon-btn" onClick={onClose}>✕</button>
    </div>
    <div className="drawer-body">
      <div className="col" style={{gap: 16}}>
        {fields.map((f, i) => (
          <div key={i}>
            <div className="dim" style={{fontSize: 11, fontFamily: 'IBM Plex Mono', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6}}>{f.label}</div>
            {f.type === 'select' ? (
              <select style={formFieldStyle} defaultValue={f.default}>
                {f.options.map(o => <option key={o}>{o}</option>)}
              </select>
            ) : f.type === 'textarea' ? (
              <textarea rows={4} placeholder={f.placeholder} defaultValue={f.default} style={{...formFieldStyle, resize: 'vertical'}}/>
            ) : (
              <input placeholder={f.placeholder} defaultValue={f.default} style={formFieldStyle}/>
            )}
          </div>
        ))}
      </div>
      <div className="row" style={{justifyContent: 'flex-end', gap: 8, marginTop: 24, paddingTop: 18, borderTop: '1px solid var(--border)'}}>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={() => { onSubmit?.(); onClose(); }}>{submitLabel}</button>
      </div>
    </div>
  </Drawer>
);

Object.assign(window, {
  Icon, KPI, Sparkline, BarHisto, AreaChart, Donut,
  Sev, Status, Tabs, Toggle, Drawer, MitreHeatmap,
  cn, fmt, timeAgo, RiskMarker, Section, Empty, CoverageGauge,
  showToast, ToastHost, IconMenu, SimpleFormDrawer, formFieldStyle,
});
