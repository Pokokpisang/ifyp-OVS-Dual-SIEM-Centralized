document.addEventListener('DOMContentLoaded', () => {
    const hostSelect = document.getElementById('hostSelect');

    // Init Charts
    const cpuCtx = document.getElementById('cpuChart').getContext('2d');
    const netCtx = document.getElementById('netChart').getContext('2d');

    Chart.defaults.color = '#888';
    Chart.defaults.borderColor = '#332f36';

    const cpuChart = new Chart(cpuCtx, {
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

    const netChart = new Chart(netCtx, {
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

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function severityBadge(sev) {
        const s = (sev || '').toUpperCase();
        if (s === 'HIGH' || s === 'CRITICAL') {
            return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">
                        <span class="w-1 h-1 rounded-full bg-red-400 inline-block"></span>${s}
                    </span>`;
        }
        if (s === 'MED' || s === 'MEDIUM' || s === 'WARNING') {
            return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        <span class="w-1 h-1 rounded-full bg-amber-400 inline-block"></span>${s}
                    </span>`;
        }
        return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    <span class="w-1 h-1 rounded-full bg-blue-400 inline-block"></span>${escapeHtml(s) || 'INFO'}
                </span>`;
    }

    function mitreBadge(mitre_id) {
        if (!mitre_id || !mitre_id.startsWith('T')) return '';
        return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold bg-violet-500/10 text-violet-400 border border-violet-500/20">
                    <span class="material-symbols-outlined text-[10px]">shield</span>${escapeHtml(mitre_id)}
                </span>`;
    }

    function renderAlertCard(a) {
        const isMitre = a.source && a.source.startsWith && a.source.startsWith('T');
        const mitre_id = isMitre ? a.source : (a.mitre_id || '');
        const ts = new Date(a.timestamp || a.timestamp_utc);
        const cmdMatch = (a.description || '').match(/Command(?:\s+Line)?:\s*(.+?)\.\s*Agent/i);
        const cmdExcerpt = cmdMatch ? cmdMatch[1] : '';
        const alertId = parseInt(a.id, 10) || 0;

        return `<div class="group p-3.5 rounded-xl border transition-all duration-200 relative ${
            (a.severity||'').toUpperCase() === 'HIGH' || (a.severity||'').toUpperCase() === 'CRITICAL'
                ? 'border-red-500/25 bg-red-500/5 hover:bg-red-500/10'
                : 'border-slate-200/20 bg-slate-800/30 hover:bg-slate-700/20'
        } ${!a.is_read ? 'ring-1 ring-primary/20 shadow-lg shadow-primary/5' : ''}">
            ${!a.is_read ? '<span class="absolute top-2 right-2 flex h-2 w-2"><span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span><span class="relative inline-flex rounded-full h-2 w-2 bg-primary"></span></span>' : ''}
            
            <div class="flex items-start justify-between gap-2 mb-2">
                <div class="flex items-center gap-1.5 flex-wrap">
                    ${severityBadge(a.severity)}
                    ${mitreBadge(mitre_id)}
                    ${!a.is_read ? '<span class="text-[9px] font-bold px-1.5 py-0.5 rounded bg-primary text-white uppercase">New</span>' : ''}
                </div>
                <span class="text-[10px] text-slate-500 whitespace-nowrap">${ts.toLocaleTimeString()}</span>
            </div>
            <p class="text-xs font-semibold text-slate-200 mb-1 leading-snug">${escapeHtml(a.title || 'Alert')}</p>
            ${cmdExcerpt ? `<code class="block text-[10px] px-2 py-1 mt-1 rounded bg-slate-900/60 text-amber-300 font-mono truncate" title="${escapeHtml(cmdExcerpt)}">${escapeHtml(cmdExcerpt)}</code>` : ''}
            
            <div class="flex items-center justify-between mt-2">
                <div class="flex items-center gap-2 text-[10px] text-slate-500">
                    <span class="material-symbols-outlined text-[11px]">terminal</span>
                    <span class="font-mono">${escapeHtml(a.host || '-')}</span>
                </div>
                ${!a.is_read ? `
                <button onclick="markAsRead(${alertId})" class="p-1 rounded bg-slate-700 hover:bg-primary text-slate-400 hover:text-white transition-colors title="Mark as read">
                    <span class="material-symbols-outlined text-xs">done</span>
                </button>` : ''}
            </div>
        </div>`;
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
            const res = await fetch('/api/alerts/stats');
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

        // 4. Security Alert Feed — use /api/alerts/threats for the MITRE panel
        try {
            const res = await fetch(`/api/alerts/threats`);
            const threats = await res.json();
            const container = document.getElementById('alert-container');
            if (threats.length === 0) {
                container.innerHTML = `<div class="p-4 rounded-lg bg-slate-800/30 border border-slate-700/30 text-center">
                    <p class="text-xs text-slate-500 py-4">No MITRE detections yet. System monitoring...</p>
                </div>`;
            } else {
                container.innerHTML = threats.slice(0, 15).map(renderAlertCard).join('');
            }
        } catch (e) {
            // Fallback to generic recent alerts
            try {
                const res = await fetch(`/api/alerts/recent?limit=20&host=${host}`);
                const alerts = await res.json();
                const container = document.getElementById('alert-container');
                container.innerHTML = alerts.map(renderAlertCard).join('');
            } catch(e2) { console.error('Alerts error:', e2); }
        }
    }

    setInterval(updateData, 5000);
    updateData();

    if (hostSelect) {
        hostSelect.addEventListener('change', updateData);
    }
});
