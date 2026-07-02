document.addEventListener('DOMContentLoaded', () => {
    const hostSelect = document.getElementById('hostSelect');

    // Init Charts
    let cpuChart = null;
    let netChart = null;
    try {
        const cpuCtx = document.getElementById('cpuChart').getContext('2d');
        const netCtx = document.getElementById('netChart').getContext('2d');

        Chart.defaults.color = '#888';
        Chart.defaults.borderColor = '#332f36';

        cpuChart = new Chart(cpuCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'CPU %', data: [], borderColor: '#F05484', backgroundColor: 'rgba(240,84,132,0.08)', fill: true, tension: 0.4, pointRadius: 0 },
                    { label: 'RAM %', data: [], borderColor: '#f59b00', backgroundColor: 'rgba(245,155,0,0.08)', fill: true, tension: 0.4, pointRadius: 0 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: 'top', labels: { boxWidth: 10, padding: 16 } } },
                scales: { y: { min: 0, max: 100, grid: { color: 'rgba(255,255,255,0.04)' } } }
            }
        });

        netChart = new Chart(netCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'In (MB/s)', data: [], borderColor: '#36a2eb', backgroundColor: 'rgba(54,162,235,0.08)', fill: true, tension: 0.4, pointRadius: 0 },
                    { label: 'Out (MB/s)', data: [], borderColor: '#ce2e46', backgroundColor: 'rgba(206,46,70,0.08)', fill: true, tension: 0.4, pointRadius: 0 }
                ]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: 'top', labels: { boxWidth: 10, padding: 16 } } },
                scales: { y: { min: 0, grid: { color: 'rgba(255,255,255,0.04)' } } }
            }
        });
    } catch (e) {
        console.warn('Chart.js unavailable, charts disabled:', e);
    }

    function buildSeverityBadge(sev) {
        const s = (sev || '').toUpperCase();
        const span = document.createElement('span');
        span.className = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold';
        const dot = document.createElement('span');
        dot.className = 'w-1 h-1 rounded-full inline-block';
        if (s === 'HIGH' || s === 'CRITICAL') {
            span.classList.add('bg-red-500/10', 'text-red-400', 'border', 'border-red-500/20');
            dot.classList.add('bg-red-400');
        } else if (s === 'MED' || s === 'MEDIUM' || s === 'WARNING') {
            span.classList.add('bg-amber-500/10', 'text-amber-400', 'border', 'border-amber-500/20');
            dot.classList.add('bg-amber-400');
        } else {
            span.classList.add('bg-blue-500/10', 'text-blue-400', 'border', 'border-blue-500/20');
            dot.classList.add('bg-blue-400');
        }
        span.appendChild(dot);
        span.appendChild(document.createTextNode(s || 'INFO'));
        return span;
    }

    function buildMitreBadge(mitre_id) {
        if (!mitre_id || !mitre_id.startsWith('T')) return null;
        const span = document.createElement('span');
        span.className = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold bg-violet-500/10 text-violet-400 border border-violet-500/20';
        const icon = document.createElement('span');
        icon.className = 'material-symbols-outlined text-[10px]';
        icon.textContent = 'shield';
        span.appendChild(icon);
        span.appendChild(document.createTextNode(mitre_id));
        return span;
    }

    function buildAlertCard(a) {
        const isMitre = a.source && a.source.startsWith && a.source.startsWith('T');
        const mitre_id = isMitre ? a.source : (a.mitre_id || '');
        const ts = new Date(a.timestamp || a.timestamp_utc);
        const cmdMatch = (a.description || '').match(/Command(?:\s+Line)?:\s*(.+?)\.\s*Agent/i);
        const cmdExcerpt = cmdMatch ? cmdMatch[1] : '';
        const alertId = parseInt(a.id, 10) || 0;
        const isHigh = (a.severity || '').toUpperCase() === 'HIGH' || (a.severity || '').toUpperCase() === 'CRITICAL';

        // Root card
        const card = document.createElement('div');
        card.className = [
            'group p-3.5 rounded-xl border transition-all duration-200 relative',
            isHigh ? 'border-red-500/25 bg-red-500/5 hover:bg-red-500/10'
                   : 'border-slate-200/20 bg-slate-800/30 hover:bg-slate-700/20',
            !a.is_read ? 'ring-1 ring-primary/20 shadow-lg shadow-primary/5' : ''
        ].filter(Boolean).join(' ');

        // Unread ping indicator — static markup, no server data
        if (!a.is_read) {
            const ping = document.createElement('span');
            ping.className = 'absolute top-2 right-2 flex h-2 w-2';
            ping.innerHTML = '<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>'
                           + '<span class="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>';
            card.appendChild(ping);
        }

        // Header row: badges + timestamp
        const header = document.createElement('div');
        header.className = 'flex items-start justify-between gap-2 mb-2';

        const badgeGroup = document.createElement('div');
        badgeGroup.className = 'flex items-center gap-1.5 flex-wrap';
        badgeGroup.appendChild(buildSeverityBadge(a.severity));
        const mitreBadgeEl = buildMitreBadge(mitre_id);
        if (mitreBadgeEl) badgeGroup.appendChild(mitreBadgeEl);
        if (!a.is_read) {
            const newBadge = document.createElement('span');
            newBadge.className = 'text-[9px] font-bold px-1.5 py-0.5 rounded bg-primary text-white uppercase';
            newBadge.textContent = 'New';
            badgeGroup.appendChild(newBadge);
        }
        header.appendChild(badgeGroup);

        const timeEl = document.createElement('span');
        timeEl.className = 'text-[10px] text-slate-500 whitespace-nowrap';
        timeEl.textContent = ts.toLocaleTimeString();
        header.appendChild(timeEl);
        card.appendChild(header);

        // Alert title
        const titleEl = document.createElement('p');
        titleEl.className = 'text-xs font-semibold text-slate-200 mb-1 leading-snug';
        titleEl.textContent = a.title || 'Alert';
        card.appendChild(titleEl);

        // Command excerpt (conditional)
        if (cmdExcerpt) {
            const code = document.createElement('code');
            code.className = 'block text-[10px] px-2 py-1 mt-1 rounded bg-slate-900/60 text-amber-300 font-mono truncate';
            code.setAttribute('title', cmdExcerpt);
            code.textContent = cmdExcerpt;
            card.appendChild(code);
        }

        // Footer row: host + mark-read button
        const footer = document.createElement('div');
        footer.className = 'flex items-center justify-between mt-2';

        const hostGroup = document.createElement('div');
        hostGroup.className = 'flex items-center gap-2 text-[10px] text-slate-500';
        const termIcon = document.createElement('span');
        termIcon.className = 'material-symbols-outlined text-[11px]';
        termIcon.textContent = 'terminal';
        hostGroup.appendChild(termIcon);
        const hostSpan = document.createElement('span');
        hostSpan.className = 'font-mono';
        hostSpan.textContent = a.host || '-';
        hostGroup.appendChild(hostSpan);
        footer.appendChild(hostGroup);

        if (!a.is_read) {
            const btn = document.createElement('button');
            btn.className = 'p-1 rounded bg-slate-700 hover:bg-primary text-slate-400 hover:text-white transition-colors';
            btn.setAttribute('title', 'Mark as read');
            btn.addEventListener('click', () => window.markAsRead(alertId));
            const doneIcon = document.createElement('span');
            doneIcon.className = 'material-symbols-outlined text-xs';
            doneIcon.textContent = 'done';
            btn.appendChild(doneIcon);
            footer.appendChild(btn);
        }
        card.appendChild(footer);

        return card;
    }

    window.markAsRead = async (id) => {
        try {
            await fetch(`/api/alerts/${id}/read`, { method: 'PUT' });
            updateData(); // Refresh UI
        } catch(e) { console.error('Mark read error:', e); }
    };

    window.markAllRead = async () => {
        try {
            await fetch(`/api/alerts/mark-all-read`, { method: 'POST' });
            updateData(); // Refresh UI
        } catch(e) { console.error('Mark all read error:', e); }
    };

    async function updateData() {
        const host = hostSelect ? hostSelect.value : '';

        // 1. Summary KPIs
        try {
            const res = await fetch(`/api/metrics/summary?host=${host}`);
            const data = await res.json();
            if (data.cpu_percent !== undefined) {
                document.getElementById('kpi-cpu').innerText = data.cpu_percent.toFixed(1) + '%';
                document.getElementById('kpi-ram').innerText = data.ram_percent.toFixed(1) + '%';
                document.getElementById('kpi-net-in').innerText = (data.net_in_rate / 1024 / 1024).toFixed(2) + ' MB/s';
                document.getElementById('kpi-net-out').innerText = (data.net_out_rate / 1024 / 1024).toFixed(2) + ' MB/s';
            }
        } catch (e) { console.error('Summary error:', e); }

        // 2. Alert stats KPIs
        try {
            const res = await fetch(`/api/alerts/stats?host=${host}`);
            const stats = await res.json();
            
            const el = document.getElementById('kpi-mitre');
            if (el) {
                if (stats.unread_mitre > 0) {
                    el.innerHTML = `${parseInt(stats.mitre_detections, 10) || 0} <span class="text-[10px] font-bold bg-primary/20 text-primary px-1.5 py-0.5 rounded-full ml-2">+${parseInt(stats.unread_mitre, 10) || 0} NEW</span>`;
                } else {
                    el.innerText = stats.mitre_detections || 0;
                }
            }
            
            const el2 = document.getElementById('kpi-high-severity');
            if (el2) {
                if (stats.unread_high > 0) {
                    el2.innerHTML = `${parseInt(stats.high_severity, 10) || 0} <span class="text-[10px] font-bold bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded-full ml-2">+${parseInt(stats.unread_high, 10) || 0} NEW</span>`;
                } else {
                    el2.innerText = stats.high_severity || 0;
                }
            }
        } catch(e) { console.error('Stats error:', e); }

        // 3. Timeseries Charts
        if (cpuChart && netChart) {
            try {
                const res = await fetch(`/api/metrics/timeseries?minutes=10&host=${host}`);
                const data = await res.json();

                cpuChart.data.labels = data.labels.map(t => new Date(t).toLocaleTimeString());
                cpuChart.data.datasets[0].data = data.cpu;
                cpuChart.data.datasets[1].data = data.ram;
                cpuChart.update('none');

                netChart.data.labels = data.labels.map(t => new Date(t).toLocaleTimeString());
                netChart.data.datasets[0].data = data.net_in.map(v => v / 1024 / 1024);
                netChart.data.datasets[1].data = data.net_out.map(v => v / 1024 / 1024);
                netChart.update('none');
            } catch (e) { console.error('Timeseries error:', e); }
        }

        // 4. Security Alert Feed — use /api/alerts/threats for the MITRE panel
        try {
            const res = await fetch(`/api/alerts/threats?host=${host}`);
            const threats = await res.json();
            const container = document.getElementById('alert-container');
            if (threats.length === 0) {
                container.innerHTML = `<div class="p-4 rounded-lg bg-slate-800/30 border border-slate-700/30 text-center">
                    <p class="text-xs text-slate-500 py-4">No MITRE detections yet. System monitoring...</p>
                </div>`;
            } else {
                const frag = document.createDocumentFragment();
                threats.slice(0, 15).forEach(a => frag.appendChild(buildAlertCard(a)));
                container.replaceChildren(frag);
            }
        } catch (e) {
            // Fallback to generic recent alerts
            try {
                const res = await fetch(`/api/alerts/recent?limit=20&host=${host}`);
                const alerts = await res.json();
                const container = document.getElementById('alert-container');
                const frag2 = document.createDocumentFragment();
                alerts.forEach(a => frag2.appendChild(buildAlertCard(a)));
                container.replaceChildren(frag2);
            } catch(e2) { console.error('Alerts error:', e2); }
        }
    }

    // Restore previously selected host from localStorage
    if (hostSelect) {
        const saved = localStorage.getItem('ovs_dashboard_host') || '';
        const match = Array.from(hostSelect.options).find(o => o.value === saved);
        if (match) hostSelect.value = saved;

        hostSelect.addEventListener('change', () => {
            localStorage.setItem('ovs_dashboard_host', hostSelect.value);
            updateData();
        });
    }

    window.updateData = updateData;

    setInterval(updateData, 5000);
    updateData();
});
