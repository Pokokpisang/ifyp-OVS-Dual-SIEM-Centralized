/* eslint-disable */
// OVS SOC — Audit Trail (System → Audit Trail)
// Read-only platform activity: who did what, when, to which object,
// what changed, and whether it's security-sensitive.

// --- Action category colors (extend the palette with matched oklch tints
//     that share chroma/lightness with the system's info/ok/high) ---
const AUDIT_PURPLE = 'oklch(0.72 0.12 305)';
const AUDIT_TEAL   = 'oklch(0.74 0.10 178)';
const AUDIT_CYAN   = 'oklch(0.76 0.11 215)';

const ACTION_COLOR = {
  LOGIN_SUCCESS: 'var(--ok)',
  LOGIN_FAILURE: 'var(--crit)',
  LOGOUT: 'var(--text-dim)',
  SOAR_RUN: 'var(--info)',
  SOAR_APPROVE: 'var(--ok)',
  SOAR_REJECT: 'var(--high)',
  ALERT_STATUS_CHANGED: AUDIT_PURPLE,
  AGENT_REGISTERED: AUDIT_TEAL,
  AGENT_DEREGISTERED: 'var(--text-dim)',
  AGENT_KEY_ROTATED: 'var(--accent)',
  AI_TRIAGE_REQUESTED: AUDIT_CYAN,
  AI_TRIAGE_COMPLETED: AUDIT_CYAN,
  SYSTEM_CONFIG_CHANGED: 'var(--text-muted)',
  SYSTEM_LOGIN_POLICY: 'var(--text-muted)',
};

const ActionBadge = ({ action }) => {
  const c = ACTION_COLOR[action] || 'var(--text-dim)';
  return (
    <span className="badge" style={{ color: c, background: `color-mix(in oklch, ${c} 16%, transparent)` }}>
      {action}
    </span>
  );
};

const RESULT_CLASS = {
  Approved: 'ok', Executed: 'ok', Success: 'ok', Completed: 'ok', Registered: 'ok',
  Updated: 'info', Rotated: 'info', Queued: 'high', Rejected: 'crit', Failed: 'crit', Removed: 'muted',
};
const ResultBadge = ({ result }) => <span className={`badge ${RESULT_CLASS[result] || 'muted'}`}>{result}</span>;

const AuditObject = ({ e }) => e.objId ? (
  <span className="mono" style={{ fontSize: 11.5 }}>
    <span className="dim">{e.objType}</span>
    <span style={{ color: 'var(--text-dim)' }}>:</span>
    <span>{e.objId}</span>
  </span>
) : <span className="mono dim" style={{ fontSize: 11.5 }}>{e.objType}</span>;

const SensitiveChip = () => (
  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, whiteSpace: 'nowrap', fontFamily: 'IBM Plex Mono', fontSize: 11, color: 'var(--text-dim)', background: 'var(--bg-elev)', border: '1px dashed var(--border-strong)', borderRadius: 5, padding: '2px 8px' }}>
    <Icon name="key" size={11} /> Sensitive value hidden
  </span>
);

const auditSelectStyle = { background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--text)', padding: '5px 9px', borderRadius: 6, fontSize: 12, fontFamily: 'IBM Plex Sans', outline: 'none', cursor: 'pointer' };

const AUDIT_CATEGORIES = ['All', 'Authentication', 'SOAR', 'Alert', 'Agent', 'AI Triage', 'System'];
const AUDIT_OBJ_TYPES = ['all', 'alert', 'agent', 'soar_execution', 'auth', 'ai_triage', 'system'];
const AUDIT_PER_PAGE = 12;

const AUDIT_SUMMARY = [
  { icon: 'activity', label: 'Total Events', value: '1,284', sub: 'Last 24h', c: 'var(--primary)' },
  { icon: 'key', label: 'Failed Logins', value: '23', sub: 'Last 24h', c: 'var(--crit)' },
  { icon: 'soar', label: 'SOAR Actions', value: '47', sub: 'Last 24h', c: 'var(--info)' },
  { icon: 'agent', label: 'Agent Changes', value: '9', sub: 'Last 7 days', c: 'var(--accent)' },
  { icon: 'alert', label: 'Alert Status Changes', value: '61', sub: 'Last 24h', c: AUDIT_PURPLE },
  { icon: 'ai', label: 'AI Triage Requests', value: '138', sub: 'Last 24h', c: AUDIT_CYAN },
];

// =============================================================
// AUDIT TRAIL PAGE
// =============================================================
const AuditTrailPage = ({ onNav }) => {
  const [category, setCategory] = useState('All');
  const [actor, setActor] = useState('all');
  const [objType, setObjType] = useState('all');
  const [objId, setObjId] = useState('');
  const [query, setQuery] = useState('');
  const [range, setRange] = useState('24h');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [openEvent, setOpenEvent] = useState(null);

  const actors = useMemo(() => Array.from(new Set(AUDIT_EVENTS.map(e => e.actor))), []);

  // Brief loading state on mount (demonstrates skeleton) and on Apply.
  useEffect(() => {
    const t = setTimeout(() => setLoading(false), 480);
    return () => clearTimeout(t);
  }, []);

  // Reset to first page whenever filters change.
  useEffect(() => { setPage(1); }, [category, actor, objType, objId, query, range]);

  const hasFilters = category !== 'All' || actor !== 'all' || objType !== 'all' || objId !== '' || query !== '';

  const filtered = useMemo(() => AUDIT_EVENTS.filter(e => {
    if (category !== 'All' && e.category !== category) return false;
    if (actor !== 'all' && e.actor !== actor) return false;
    if (objType !== 'all' && e.objType !== objType) return false;
    if (objId && !String(e.objId || '').includes(objId)) return false;
    if (query) {
      const q = query.toLowerCase();
      const hay = [e.actor, e.action, e.objType, e.objId, e.result, ...e.details.flat()].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }), [category, actor, objType, objId, query]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / AUDIT_PER_PAGE));
  const clampedPage = Math.min(page, pageCount);
  const start = (clampedPage - 1) * AUDIT_PER_PAGE;
  const pageRows = filtered.slice(start, start + AUDIT_PER_PAGE);

  const runApply = () => { setLoading(true); setTimeout(() => setLoading(false), 480); showToast(`Applied filters · ${filtered.length} records`); };
  const resetFilters = () => { setCategory('All'); setActor('all'); setObjType('all'); setObjId(''); setQuery(''); setRange('24h'); showToast('Filters reset'); };

  return (
    <div className="page" data-screen-label="Audit Trail">
      <div className="page-header">
        <div>
          <h1 className="page-title">Audit Trail</h1>
          <div className="page-sub">Review analyst, system, SOAR, agent, authentication, and AI-triage activity across the platform.</div>
        </div>
        <div className="page-actions">
          <span className="mode-pill" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Icon name="shield" size={11} /> Read-only
          </span>
          <button className="btn" onClick={() => showToast(`Exporting ${filtered.length} audit records to CSV…`)}><Icon name="download" size={13} /> Export</button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="kpi-row">
        {AUDIT_SUMMARY.map(s => (
          <div className="kpi" key={s.label}>
            <div className="kpi-label">
              <span style={{ color: s.c, display: 'flex' }}><Icon name={s.icon} size={13} /></span>
              {s.label}
            </div>
            <div className="kpi-value tnum"><span style={{ color: s.c }}>{s.value}</span></div>
            <div className="kpi-foot"><span className="dim">{s.sub}</span></div>
          </div>
        ))}
      </div>

      {/* Filter bar — row 1: search + action-type chips */}
      <div className="filters">
        <div className="search" style={{ width: 280 }}>
          <Icon name="search" size={13} />
          <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search actor, action, object, details…" />
        </div>
        <span className="dim" style={{ fontSize: 11, marginLeft: 6 }}>ACTION</span>
        {AUDIT_CATEGORIES.map(c => (
          <span key={c} className={`filter-chip ${category === c ? 'active' : ''}`} onClick={() => setCategory(c)}>
            {c === 'All' ? 'ALL' : c.toUpperCase()}
          </span>
        ))}
      </div>

      {/* Filter bar — row 2: structured filters + actions */}
      <div className="filters">
        <label className="row" style={{ gap: 6 }}>
          <span className="dim" style={{ fontSize: 11 }}>DATE RANGE</span>
          <select style={auditSelectStyle} value={range} onChange={e => setRange(e.target.value)}>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="custom">Custom range…</option>
          </select>
        </label>
        <label className="row" style={{ gap: 6 }}>
          <span className="dim" style={{ fontSize: 11 }}>ACTOR</span>
          <select style={auditSelectStyle} value={actor} onChange={e => setActor(e.target.value)}>
            <option value="all">All actors</option>
            {actors.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        </label>
        <label className="row" style={{ gap: 6 }}>
          <span className="dim" style={{ fontSize: 11 }}>OBJECT TYPE</span>
          <select style={auditSelectStyle} value={objType} onChange={e => setObjType(e.target.value)}>
            {AUDIT_OBJ_TYPES.map(o => <option key={o} value={o}>{o === 'all' ? 'All types' : o}</option>)}
          </select>
        </label>
        <label className="row" style={{ gap: 6 }}>
          <span className="dim" style={{ fontSize: 11 }}>OBJECT ID</span>
          <input value={objId} onChange={e => setObjId(e.target.value)} placeholder="e.g. 42"
            style={{ ...auditSelectStyle, width: 84, fontFamily: 'IBM Plex Mono', cursor: 'text' }} />
        </label>
        <span style={{ flex: 1 }} />
        <button className="btn btn-sm" onClick={resetFilters}><Icon name="refresh" size={11} /> Reset</button>
        <button className="btn btn-sm btn-primary" onClick={runApply}><Icon name="filter" size={11} /> Apply filters</button>
      </div>

      {/* Audit table */}
      <div className="row" style={{ gap: 8, fontSize: 11.5, color: 'var(--text-dim)', padding: '0 2px' }}>
        <Icon name="shield" size={13} />
        <span>Audit events are read-only and cannot be modified from this page. Records are retained per your workspace retention policy.</span>
      </div>
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 156 }}>Time</th>
              <th style={{ width: 168 }}>Actor</th>
              <th style={{ width: 220 }}>Action</th>
              <th style={{ width: 150 }}>Object</th>
              <th style={{ width: 116 }}>Result</th>
              <th style={{ width: 84 }}>Details</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 8 }).map((_, i) => (
                <tr key={`sk-${i}`}>
                  <td><div className="skel" style={{ width: 120 }} /></td>
                  <td><div className="skel" style={{ width: 96 }} /></td>
                  <td><div className="skel" style={{ width: 150 }} /></td>
                  <td><div className="skel" style={{ width: 70 }} /></td>
                  <td><div className="skel" style={{ width: 64 }} /></td>
                  <td><div className="skel" style={{ width: 40 }} /></td>
                </tr>
              ))
            ) : pageRows.map(e => (
              <tr key={e.id} className="row-link clickable" onClick={() => setOpenEvent(e)}>
                <td className="mono dim" style={{ fontSize: 11.5, whiteSpace: 'nowrap' }}>{e.ts}</td>
                <td>
                  <div className="row" style={{ gap: 8 }}>
                    <span className={`host-dot ${e.actor.startsWith('system') ? 'silent' : 'online'}`} style={{ flexShrink: 0 }} />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontWeight: 500 }} className={e.actor.startsWith('system') ? 'mono' : ''}>{e.actor}</div>
                      <div className="dim" style={{ fontSize: 10.5 }}>{e.actorRole}</div>
                    </div>
                  </div>
                </td>
                <td>
                  <div className="row" style={{ gap: 6 }}>
                    <ActionBadge action={e.action} />
                    {e.sensitive && <span title="Security-sensitive" style={{ color: 'var(--accent)', display: 'flex' }}><Icon name="key" size={12} /></span>}
                  </div>
                </td>
                <td><AuditObject e={e} /></td>
                <td><ResultBadge result={e.result} /></td>
                <td onClick={ev => { ev.stopPropagation(); setOpenEvent(e); }}>
                  <span className="row" style={{ gap: 4, color: 'var(--primary)', fontWeight: 500, fontSize: 12 }}>
                    View <Icon name="chevron" size={12} />
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* No-result / empty state */}
        {!loading && filtered.length === 0 && (
          hasFilters ? (
            <Empty icon="search" title="No matching audit activity"
              sub="No records match the current filters."
              action={<button className="btn btn-sm" onClick={resetFilters}><Icon name="refresh" size={11} /> Clear filters</button>} />
          ) : (
            <Empty icon="file" title="No audit events found"
              sub="Try adjusting the filters or selecting a wider date range." />
          )
        )}

        {/* Pagination */}
        {!loading && filtered.length > 0 && (
          <div className="row" style={{ justifyContent: 'space-between', padding: '10px 12px', borderTop: '1px solid var(--border)' }}>
            <span className="dim mono" style={{ fontSize: 11 }}>
              Showing {start + 1}–{Math.min(start + AUDIT_PER_PAGE, filtered.length)} of {filtered.length} records
            </span>
            <div className="row" style={{ gap: 4 }}>
              <button className="btn btn-sm" disabled={clampedPage === 1}
                style={{ opacity: clampedPage === 1 ? 0.4 : 1 }}
                onClick={() => setPage(p => Math.max(1, p - 1))}>Prev</button>
              {Array.from({ length: pageCount }).map((_, i) => (
                <button key={i} className={`btn btn-sm ${clampedPage === i + 1 ? 'btn-primary' : ''}`}
                  style={{ minWidth: 30, justifyContent: 'center' }}
                  onClick={() => setPage(i + 1)}>{i + 1}</button>
              ))}
              <button className="btn btn-sm" disabled={clampedPage === pageCount}
                style={{ opacity: clampedPage === pageCount ? 0.4 : 1 }}
                onClick={() => setPage(p => Math.min(pageCount, p + 1))}>Next</button>
            </div>
          </div>
        )}
      </div>

      {openEvent && <AuditDetailDrawer e={openEvent} onClose={() => setOpenEvent(null)} onNav={onNav} />}
    </div>
  );
};

// =============================================================
// AUDIT DETAIL DRAWER
// =============================================================
const AuditField = ({ label, children }) => (
  <div style={{ display: 'flex', gap: 16, padding: '9px 0', borderBottom: '1px solid var(--border)' }}>
    <div className="dim" style={{ fontFamily: 'IBM Plex Mono', fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.08em', width: 96, flexShrink: 0, paddingTop: 1 }}>{label}</div>
    <div style={{ flex: 1, fontSize: 13 }}>{children}</div>
  </div>
);

const AuditDetailDrawer = ({ e, onClose, onNav }) => {
  const openRelated = (r) => {
    if (r.page) { onNav && onNav(r.page); onClose(); }
    else showToast('Login context is available in the authentication logs.');
  };
  return (
    <Drawer open={true} onClose={onClose}>
      <div className="drawer-header">
        <div>
          <div className="dim mono" style={{ fontSize: 11, marginBottom: 6 }}>Audit Event · {e.id}</div>
          <div className="row" style={{ gap: 8, marginBottom: 4 }}>
            <ActionBadge action={e.action} />
            <ResultBadge result={e.result} />
            {e.sensitive && <span className="badge" style={{ color: 'var(--accent)', background: 'var(--accent-soft)' }}>Sensitive</span>}
          </div>
          <div style={{ fontSize: 17, fontWeight: 600, marginTop: 6 }}>Audit Event Details</div>
        </div>
        <button className="icon-btn" onClick={onClose}>✕</button>
      </div>
      <div className="drawer-body">
        <div style={{ marginBottom: 20 }}>
          <AuditField label="Time"><span className="mono">{e.ts}</span></AuditField>
          <AuditField label="Actor">
            <span className="row" style={{ gap: 8 }}>
              <span className={`host-dot ${e.actor.startsWith('system') ? 'silent' : 'online'}`} />
              <span style={{ fontWeight: 500 }}>{e.actor}</span>
              <span className="dim" style={{ fontSize: 12 }}>· {e.actorRole}</span>
            </span>
          </AuditField>
          <AuditField label="Action"><ActionBadge action={e.action} /></AuditField>
          <AuditField label="Object Type"><span className="mono">{e.objType}</span></AuditField>
          <AuditField label="Object ID">{e.objId ? <span className="mono">{e.objId}</span> : <span className="dim">—</span>}</AuditField>
          <AuditField label="Result"><ResultBadge result={e.result} /></AuditField>
          <AuditField label="Source"><span className="mono">{e.source}</span></AuditField>
        </div>

        {/* Details (key/value) */}
        <div className="card-title" style={{ marginBottom: 8 }}>Details</div>
        <div style={{ border: '1px solid var(--border)', borderRadius: 7, overflow: 'hidden' }}>
          {e.details.map(([k, v], i) => (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: 12, alignItems: 'center', padding: '9px 12px', background: i % 2 ? 'transparent' : 'var(--bg-elev)', borderBottom: i < e.details.length - 1 ? '1px solid var(--border)' : 'none' }}>
              <span className="mono" style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>{k}</span>
              {v === '__SENSITIVE__'
                ? <SensitiveChip />
                : <span className="mono" style={{ fontSize: 11.5, color: 'var(--text)' }}>{v}</span>}
            </div>
          ))}
        </div>

        {/* Related links */}
        {e.related && e.related.length > 0 && (
          <>
            <div className="card-title" style={{ margin: '20px 0 8px' }}>Related</div>
            <div className="row wrap" style={{ gap: 8 }}>
              {e.related.map((r, i) => (
                <button key={i} className="btn btn-sm" onClick={() => openRelated(r)}>
                  <Icon name="link" size={11} /> {r.label}
                </button>
              ))}
            </div>
          </>
        )}

        <div className="row" style={{ gap: 7, marginTop: 22, paddingTop: 16, borderTop: '1px solid var(--border)', fontSize: 11.5, color: 'var(--text-dim)' }}>
          <Icon name="shield" size={13} />
          <span>This record is read-only. Sensitive values (keys, tokens, secrets) are never stored or displayed.</span>
        </div>
      </div>
    </Drawer>
  );
};

Object.assign(window, { AuditTrailPage });
