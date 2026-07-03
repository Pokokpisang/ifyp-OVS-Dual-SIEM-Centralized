/* eslint-disable */
// OVS SOC — App shell, sidebar, topbar, router, tweaks

const { useState, useEffect, useMemo, useRef } = React;

const NAV_ADMIN = [
  { group: 'COMMAND', items: [
    { id: 'overview', label: 'Overview', icon: 'overview' },
    { id: 'alerts', label: 'Alerts', icon: 'alert', badge: 7 },
    { id: 'investigation', label: 'Investigation', icon: 'investigate' },
  ]},
  { group: 'ASSETS', items: [
    { id: 'agents', label: 'Agents', icon: 'agent' },
    { id: 'clients', label: 'Clients', icon: 'clients' },
    { id: 'network', label: 'Network', icon: 'network' },
  ]},
  { group: 'DETECTION', items: [
    { id: 'rules', label: 'Detection Rules', icon: 'rule' },
    { id: 'ai', label: 'AI Triage', icon: 'ai' },
  ]},
  { group: 'RESPONSE', items: [
    { id: 'soar', label: 'SOAR', icon: 'soar', badge: 2 },
    { id: 'soar-history', label: 'SOAR History', icon: 'history' },
  ]},
  { group: 'ADMIN', items: [
    { id: 'reports', label: 'Reports', icon: 'reports' },
    { id: 'notifications', label: 'Notifications', icon: 'bell' },
    { id: 'rbac', label: 'Users & RBAC', icon: 'rbac' },
  ]},
  { group: 'SYSTEM', items: [
    { id: 'settings', label: 'Settings', icon: 'settings' },
    { id: 'audit-trail', label: 'Audit Trail', icon: 'history' },
  ]},
];

const NAV_CLIENT = [
  { group: 'PORTAL', items: [
    { id: 'cp-overview', label: 'Overview', icon: 'overview' },
    { id: 'cp-agents', label: 'My Agents', icon: 'agent' },
    { id: 'cp-events', label: 'Security Events', icon: 'shield' },
  ]},
  { group: 'REPORTING', items: [
    { id: 'cp-reports', label: 'Reports', icon: 'reports' },
    { id: 'cp-posture', label: 'Monthly Posture', icon: 'trend' },
  ]},
  { group: 'ACCOUNT', items: [
    { id: 'cp-support', label: 'Support', icon: 'headset' },
    { id: 'cp-settings', label: 'My Account', icon: 'user' },
  ]},
];

// --- Sidebar ---
const Sidebar = ({ active, onNav, mode, open }) => {
  const nav = mode === 'client' ? NAV_CLIENT : NAV_ADMIN;
  return (
    <aside className={`sidebar ${open ? 'open' : ''}`}>
      <div className="brand">
        <img src={window.__resources ? window.__resources.ovsIcon : "assets/ovs-icon.png"} alt="OVS" className="brand-mark-img"/>
        <div>
          <div className="brand-name">OVS</div>
          <div className="brand-sub">{mode === 'client' ? 'Client Portal' : 'Security Ops'}</div>
        </div>
      </div>
      {nav.map(g => (
        <div className="nav-group" key={g.group}>
          <div className="nav-group-label">{g.group}</div>
          {g.items.map(it => (
            <div key={it.id}
              className={`nav-item ${active === it.id ? 'active' : ''}`}
              onClick={() => onNav(it.id)}>
              <span className="nav-icon"><Icon name={it.icon} size={15}/></span>
              <span>{it.label}</span>
              {it.badge && <span className="nav-badge">{it.badge}</span>}
            </div>
          ))}
        </div>
      ))}
      <div style={{flex: 1}}/>
      <div style={{padding: '12px 8px', borderTop: '1px solid var(--border)', marginTop: 10}}>
        <div className="muted" style={{fontSize: 11, marginBottom: 6}}>System</div>
        <div className="row" style={{gap: 6, marginBottom: 4}}>
          <span className="host-dot online"/>
          <span style={{fontSize: 11.5}} className="muted">Backend</span>
          <span className="mono dim" style={{fontSize: 10, marginLeft: 'auto'}}>v2.4.1</span>
        </div>
        <div className="row" style={{gap: 6}}>
          <span className="host-dot online"/>
          <span style={{fontSize: 11.5}} className="muted">Agent fleet</span>
          <span className="mono dim" style={{fontSize: 10, marginLeft: 'auto'}}>241/256</span>
        </div>
      </div>
    </aside>
  );
};

// --- Topbar ---
const Topbar = ({ crumbs, mode, onMenuClick }) => {
  return (
    <div className="topbar">
      <button className="icon-btn menu-btn" onClick={onMenuClick} title="Menu"><Icon name="menu" size={16}/></button>
      <div className="crumbs">
        {crumbs.map((c, i) => (
          <React.Fragment key={i}>
            {i > 0 && <span className="sep">›</span>}
            <span className={i === crumbs.length - 1 ? 'current' : ''}>{c}</span>
          </React.Fragment>
        ))}
      </div>
      <div className="spacer"/>
      <div className="search">
        <Icon name="search" size={13}/>
        <input placeholder={mode === 'client' ? 'Search agents, reports…' : 'Search alerts, agents, clients, rules…'}/>
        <span className="kbd">⌘K</span>
      </div>
      <span className="mode-pill" style={{ borderColor: mode === 'client' ? 'var(--info)' : 'var(--primary-line)', color: mode === 'client' ? 'var(--info)' : 'var(--primary)' }}>
        {mode === 'client' ? 'CLIENT VIEW' : 'ADMIN / SOC'}
      </span>
      <button className="icon-btn" title="Refresh"><Icon name="refresh" size={14}/></button>
      <button className="icon-btn" title="Notifications">
        <Icon name="bell" size={15}/>
        <span className="dot"/>
      </button>
      <div className="user-chip">
        <div className="avatar">{mode === 'client' ? 'MT' : 'PK'}</div>
        <span style={{fontSize: 12.5}}>{mode === 'client' ? 'Mei Tanaka' : 'P. Kareem'}</span>
        <span className="role">{mode === 'client' ? 'CLIENT' : 'SOC LEAD'}</span>
      </div>
    </div>
  );
};

// --- Tweaks ---
const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "viewMode": "admin",
  "density": "compact"
}/*EDITMODE-END*/;

const Tweaks = ({ tweaks, setTweak }) => (
  <TweaksPanel title="Tweaks">
    <TweakSection title="View mode">
      <TweakRadio label="Audience" value={tweaks.viewMode} options={[{label:'Admin / SOC', value:'admin'}, {label:'Client portal', value:'client'}]} onChange={v => setTweak('viewMode', v)}/>
    </TweakSection>
    <TweakSection title="Density">
      <TweakRadio label="Row height" value={tweaks.density} options={[{label:'Compact', value:'compact'}, {label:'Comfortable', value:'comfortable'}]} onChange={v => setTweak('density', v)}/>
    </TweakSection>
    <TweakSection title="Reference">
      <div style={{fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.6}}>
        Density adjusts table rows + padding system-wide. View mode swaps the entire shell (sidebar + topbar accent) between admin SOC and the read-only client portal.
      </div>
    </TweakSection>
  </TweaksPanel>
);

// --- App ---
const ROUTE_LABELS = {
  overview: ['Command Center', 'Overview'],
  alerts: ['Command Center', 'Alerts'],
  investigation: ['Command Center', 'Investigation', 'A-7842'],
  agents: ['Assets', 'Agents'],
  clients: ['Assets', 'Clients'],
  network: ['Assets', 'Network'],
  rules: ['Detection', 'Detection Rules'],
  ai: ['Detection', 'AI Triage'],
  soar: ['Response', 'SOAR'],
  'soar-history': ['Response', 'SOAR History'],
  reports: ['Admin', 'Reports'],
  notifications: ['Admin', 'Notifications'],
  rbac: ['Admin', 'Users & RBAC'],
  settings: ['System', 'Settings'],
  'audit-trail': ['System', 'Audit Trail'],
  'cp-overview': ['Halcyon Labs', 'Overview'],
  'cp-agents': ['Halcyon Labs', 'My Agents'],
  'cp-events': ['Halcyon Labs', 'Security Events'],
  'cp-reports': ['Halcyon Labs', 'Reports'],
  'cp-posture': ['Halcyon Labs', 'Monthly Posture'],
  'cp-support': ['Halcyon Labs', 'Support'],
  'cp-settings': ['Halcyon Labs', 'My Account'],
};

const App = () => {
  const [tweaks, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [active, setActive] = useState('audit-trail');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const navigate = (id) => { setActive(id); setSidebarOpen(false); };

  // Sync mode -> default route
  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', tweaks.viewMode === 'client' ? 'client' : 'dark');
    root.setAttribute('data-density', tweaks.density);
    if (tweaks.viewMode === 'client' && !active.startsWith('cp-')) setActive('cp-overview');
    if (tweaks.viewMode === 'admin' && active.startsWith('cp-')) setActive('overview');
  }, [tweaks.viewMode, tweaks.density]);

  const mode = tweaks.viewMode === 'client' ? 'client' : 'admin';
  const crumbs = ROUTE_LABELS[active] || [active];

  const renderPage = () => {
    if (mode === 'client') {
      switch (active) {
        case 'cp-overview': return <ClientOverview onNav={setActive}/>;
        case 'cp-agents': return <ClientAgents/>;
        case 'cp-events': return <ClientEvents/>;
        case 'cp-reports': return <ClientReports/>;
        case 'cp-posture': return <ClientPosture/>;
        case 'cp-support': return <ClientSupport/>;
        case 'cp-settings': return <ClientSettings/>;
        default: return <ClientOverview/>;
      }
    }
    switch (active) {
      case 'overview': return <OverviewPage onNav={setActive}/>;
      case 'alerts': return <AlertsPage onOpen={() => setActive('investigation')}/>;
      case 'investigation': return <InvestigationPage onBack={() => setActive('alerts')}/>;
      case 'agents': return <AgentsPage onNav={setActive}/>;
      case 'clients': return <ClientsPage onNav={setActive}/>;
      case 'network': return <NetworkPage onNav={setActive}/>;
      case 'rules': return <RulesPage onNav={setActive}/>;
      case 'ai': return <AITriagePage onNav={setActive}/>;
      case 'soar': return <SoarPage onNav={setActive}/>;
      case 'soar-history': return <SoarHistoryPage onNav={setActive}/>;
      case 'reports': return <ReportsPage onNav={setActive}/>;
      case 'notifications': return <NotificationsPage onNav={setActive}/>;
      case 'rbac': return <RbacPage onNav={setActive}/>;
      case 'settings': return <SettingsPage onNav={setActive}/>;
      case 'audit-trail': return <AuditTrailPage onNav={setActive}/>;
      default: return <OverviewPage onNav={setActive}/>;
    }
  };

  return (
    <div className="app" data-screen-label={mode === 'client' ? 'Client Portal' : 'Admin SOC'}>
      <Sidebar active={active} onNav={navigate} mode={mode} open={sidebarOpen}/>
      {sidebarOpen && <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)}/>}
      <div className="main">
        <Topbar crumbs={crumbs} mode={mode} onMenuClick={() => setSidebarOpen(o => !o)}/>
        <div key={active}>
          {renderPage()}
        </div>
      </div>
      <Tweaks tweaks={tweaks} setTweak={setTweak}/>
      <ToastHost/>
    </div>
  );
};

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
