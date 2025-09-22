document.addEventListener('DOMContentLoaded', function() {
    // --- CONFIGURATION ---
    const STATUS_COLORS = {
        open: '#e74c3c',
        in_progress: '#f1c40f',
        resolved: '#2ecc71',
        default: '#95a5a6'
    };
    const PRIORITY_COLORS = {
        high: '#e74c3c',
        medium: '#f39c12',
        low: '#3498db'
    };

    // --- ELEMENT REFERENCES ---
    const clearDataBtn = document.getElementById('clear-data-btn');
    const statusPieChartCtx = document.getElementById('status-pie-chart')?.getContext('2d');
    const tableBody = document.getElementById('blockers-table-body');
    const statusFilter = document.getElementById('status-filter');
    const priorityFilter = document.getElementById('priority-filter');
    const searchFilter = document.getElementById('search-filter');

    // --- DATA LOADING AND INITIALIZATION ---
    const blockersJSON = sessionStorage.getItem('Blockers');
    if (!blockersJSON) {
        window.location.href = 'index.html';
        return;
    }
    const allBlockers = JSON.parse(blockersJSON);

    // --- MAIN EXECUTION ---
    populateFilters(allBlockers);
    renderPage(allBlockers);

    // --- EVENT LISTENERS ---
    clearDataBtn.addEventListener('click', () => {
        sessionStorage.clear();
        window.location.href = 'index.html';
    });

    [statusFilter, priorityFilter, searchFilter].forEach(filter => {
        filter.addEventListener('input', () => {
            const filteredData = applyFilters(allBlockers);
            renderTable(filteredData);
        });
    });

    // --- FUNCTIONS ---

    function formatDate(excelDate) {
        if (!excelDate) return '';
        if (typeof excelDate === 'number') {
            const date = new Date((excelDate - 25569) * 86400 * 1000);
            const day = String(date.getDate()).padStart(2, '0');
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const year = date.getFullYear();
            return `${day}.${month}.${year}`;
        }
        return excelDate;
    }

    function normalizeStatus(status) {
        return status ? String(status).toLowerCase().replace(/ /g, '_') : 'open';
    }

    function renderPage(data) {
        renderSummary(data);
        renderPieChart(data);
        renderTable(data);
    }

    function renderSummary(data) {
        const statusCounts = data.reduce((acc, item) => {
            const status = normalizeStatus(item['Resolution Status']);
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        document.getElementById('total-blockers').textContent = data.length;
        document.getElementById('open-blockers').textContent = statusCounts.open || 0;
        document.getElementById('inprogress-blockers').textContent = statusCounts.in_progress || 0;
        document.getElementById('resolved-blockers').textContent = statusCounts.resolved || 0;
    }

    function renderPieChart(data) {
        if (!statusPieChartCtx) return;

        const statusCounts = data.reduce((acc, item) => {
            const status = normalizeStatus(item['Resolution Status']);
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        const labels = Object.keys(statusCounts);
        const chartData = Object.values(statusCounts);
        const backgroundColors = labels.map(label => STATUS_COLORS[label] || STATUS_COLORS.default);

        if (window.myStatusChart) {
            window.myStatusChart.destroy();
        }

        window.myStatusChart = new Chart(statusPieChartCtx, {
            type: 'doughnut',
            data: {
                labels: labels.map(l => l.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase())),
                datasets: [{
                    label: 'Blocker Status',
                    data: chartData,
                    backgroundColor: backgroundColors,
                    borderColor: '#ffffff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    }
                }
            }
        });
    }

    function renderTable(data) {
        if (!tableBody) return;
        tableBody.innerHTML = '';

        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="6">No matching blockers found.</td></tr>';
            return;
        }

        data.forEach(item => {
            const status = normalizeStatus(item['Resolution Status']);
            const priority = (item.Priority || '').toLowerCase();
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${item['Blocker Name'] || ''}</td>
                <td>${item.Description || ''}</td>
                <td>${item.Responsible || ''}</td>
                <td>${formatDate(item['Start Date'])}</td>
                <td><span class="priority-badge priority-${priority}">${priority}</span></td>
                <td><span class="status-badge status-${status}">${status.replace(/_/g, ' ')}</span></td>
            `;
            tableBody.appendChild(row);
        });
    }

    function populateFilters(data) {
        const statuses = [...new Set(data.map(item => normalizeStatus(item['Resolution Status'])))];
        const priorities = [...new Set(data.map(item => (item.Priority || '').toLowerCase()).filter(Boolean))];

        statuses.forEach(status => {
            const option = document.createElement('option');
            option.value = status;
            option.textContent = status.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
            statusFilter.appendChild(option);
        });

        priorities.forEach(priority => {
            const option = document.createElement('option');
            option.value = priority;
            option.textContent = priority.charAt(0).toUpperCase() + priority.slice(1);
            priorityFilter.appendChild(option);
        });
    }

    function applyFilters(data) {
        const status = statusFilter.value;
        const priority = priorityFilter.value;
        const searchTerm = searchFilter.value.toLowerCase();

        return data.filter(item => {
            const itemStatus = normalizeStatus(item['Resolution Status']);
            const itemPriority = (item.Priority || '').toLowerCase();
            const itemName = (item['Blocker Name'] || '').toLowerCase();
            const itemDesc = (item.Description || '').toLowerCase();

            const statusMatch = status === 'all' || itemStatus === status;
            const priorityMatch = priority === 'all' || itemPriority === priority;
            const searchMatch = searchTerm === '' || itemName.includes(searchTerm) || itemDesc.includes(searchTerm);

            return statusMatch && priorityMatch && searchMatch;
        });
    }
});
