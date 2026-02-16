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
                { label: 'CPU %', data: [], borderColor: '#F05484', tension: 0.4 },
                { label: 'RAM %', data: [], borderColor: '#f59b00', tension: 0.4 }
            ]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });

    const netChart = new Chart(netCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'In (MB/s)', data: [], borderColor: '#36a2eb', tension: 0.4 },
                { label: 'Out (MB/s)', data: [], borderColor: '#ce2e46', tension: 0.4 }
            ]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });

    async function updateData() {
        const host = hostSelect ? hostSelect.value : '';

        // 1. Summary
        try {
            const res = await fetch(`/api/metrics/summary?host=${host}`);
            const data = await res.json();
            if (data.cpu_percent !== undefined) {
                document.getElementById('kpi-cpu').innerText = data.cpu_percent.toFixed(1) + '%';
                document.getElementById('kpi-ram').innerText = data.ram_percent.toFixed(1) + '%';
                // Convert bytes/s to MB/s
                document.getElementById('kpi-net-in').innerText = (data.net_in_rate / 1024 / 1024).toFixed(2) + ' MB/s';
                document.getElementById('kpi-net-out').innerText = (data.net_out_rate / 1024 / 1024).toFixed(2) + ' MB/s';
            }
        } catch (e) { console.error(e); }

        // 2. Timeseries (Charts)
        try {
            const res = await fetch(`/api/metrics/timeseries?minutes=10&host=${host}`);
            const data = await res.json();

            cpuChart.data.labels = data.labels.map(t => new Date(t).toLocaleTimeString());
            cpuChart.data.datasets[0].data = data.cpu;
            cpuChart.data.datasets[1].data = data.ram;
            cpuChart.update();

            netChart.data.labels = data.labels.map(t => new Date(t).toLocaleTimeString());
            // Bytes -> MB
            netChart.data.datasets[0].data = data.net_in.map(v => v / 1024 / 1024);
            netChart.data.datasets[1].data = data.net_out.map(v => v / 1024 / 1024);
            netChart.update();

        } catch (e) { console.error(e); }

        // 3. Alerts
        try {
            const res = await fetch(`/api/alerts/recent?limit=20&host=${host}`);
            const alerts = await res.json();
            const container = document.getElementById('alert-container');
            container.innerHTML = alerts.map(a => `
                <div class="alert-item ${a.severity}">
                    <div class="title">${a.title}</div>
                    <div class="meta">${new Date(a.timestamp).toLocaleString()} - ${a.host}</div>
                    <div style="font-size:12px; margin-top:4px;">${a.description}</div>
                </div>
            `).join('');
        } catch (e) { console.error(e); }
    }

    // Polling
    setInterval(updateData, 2000); // Metrics fast
    updateData(); // Initial load
});
