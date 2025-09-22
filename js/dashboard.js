document.addEventListener('DOMContentLoaded', function() {
    // --- CONFIGURATION ---
    const STATUS_COLORS = {
        open: '#3498db',
        in_progress: '#f1c40f',
        completed: '#2ecc71',
        blocked: '#e74c3c',
        overdue: '#c0392b',
        default: '#95a5a6'
    };

    const exportBtn = document.getElementById('export-excel-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            exportDataToExcel(); // This function is in export.js
        });
    }

    // --- ELEMENT REFERENCES ---
    const clearDataBtn = document.getElementById('clear-data-btn');
    const statusPieChartCtx = document.getElementById('status-pie-chart')?.getContext('2d');
    const tableBody = document.getElementById('test-plan-table-body');
    const statusFilter = document.getElementById('status-filter');
    const responsibleFilter = document.getElementById('responsible-filter');
    const searchFilter = document.getElementById('search-filter');

    // --- DATA LOADING AND INITIALIZATION ---
    const testDataJSON = sessionStorage.getItem('Test Plan');
    if (!testDataJSON) {
        // If no data, redirect to home page to upload a file
        window.location.href = 'index.html';
        return;
    }
    const allTestData = JSON.parse(testDataJSON);

    // --- MAIN EXECUTION ---
    populateFilters(allTestData);
    renderPage(allTestData);

    // --- EVENT LISTENERS ---
    clearDataBtn.addEventListener('click', () => {
        sessionStorage.clear();
        window.location.href = 'index.html';
    });

    [statusFilter, responsibleFilter, searchFilter].forEach(filter => {
        filter.addEventListener('input', () => {
            const filteredData = applyFilters(allTestData);
            renderTable(filteredData);
        });
    });

    // --- FUNCTIONS ---

    function renderPage(data) {
        renderSummary(data);
        renderPieChart(data);
        renderTable(data);
    }

    function renderSummary(data) {
        const statusCounts = data.reduce((acc, item) => {
            const status = item.Status ? String(item.Status).toLowerCase().replace(' ', '_') : 'open';
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        document.getElementById('total-tests').textContent = data.length;
        document.getElementById('completed-tests').textContent = statusCounts.completed || 0;
        document.getElementById('inprogress-tests').textContent = statusCounts.in_progress || 0;
        document.getElementById('blocked-tests').textContent = statusCounts.blocked || 0;
    }

    function renderPieChart(data) {
        if (!statusPieChartCtx) return;

        const statusCounts = data.reduce((acc, item) => {
            const status = item.Status ? String(item.Status).toLowerCase().replace(' ', '_') : 'open';
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        const labels = Object.keys(statusCounts);
        const chartData = Object.values(statusCounts);
        const backgroundColors = labels.map(label => STATUS_COLORS[label] || STATUS_COLORS.default);

        // Destroy existing chart instance if it exists
        if (window.myStatusChart) {
            window.myStatusChart.destroy();
        }

        window.myStatusChart = new Chart(statusPieChartCtx, {
            type: 'doughnut',
            data: {
                labels: labels.map(l => l.replace('_', ' ').replace(/\b\w/g, char => char.toUpperCase())), // Capitalize labels
                datasets: [{
                    label: 'Test Status',
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
        tableBody.innerHTML = ''; // Clear existing table rows

        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="8">No matching tests found.</td></tr>';
            return;
        }

        data.forEach(item => {
            const status = item.Status ? String(item.Status).toLowerCase().replace(' ', '_') : 'open';
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${item.Test || ''}</td>
                <td>${item.Description || ''}</td>
                <td><span class="status-badge status-${status}">${status.replace('_', ' ')}</span></td>
                <td><div class="progress-bar"><div class="progress-bar-fill" style="width: ${item.Progress || 0}%;"></div></div> ${item.Progress || 0}%</td>
                <td>${item.Responsible || ''}</td>
                <td>${item.Location || ''}</td>
                <td>${item['Start Date'] || ''}</td>
                <td>${item['Due Date'] || ''}</td>
            `;
            tableBody.appendChild(row);
        });
    }

    function populateFilters(data) {
        const statuses = [...new Set(data.map(item => item.Status ? String(item.Status).toLowerCase().replace(' ', '_') : 'open'))];
        const responsibles = [...new Set(data.map(item => item.Responsible).filter(Boolean))]; // Filter out empty values

        statuses.forEach(status => {
            const option = document.createElement('option');
            option.value = status;
            option.textContent = status.replace('_', ' ').replace(/\b\w/g, char => char.toUpperCase());
            statusFilter.appendChild(option);
        });

        responsibles.sort().forEach(person => {
            const option = document.createElement('option');
            option.value = person;
            option.textContent = person;
            responsibleFilter.appendChild(option);
        });
    }

    function applyFilters(data) {
        const status = statusFilter.value;
        const responsible = responsibleFilter.value;
        const searchTerm = searchFilter.value.toLowerCase();

        return data.filter(item => {
            const itemStatus = item.Status ? String(item.Status).toLowerCase().replace(' ', '_') : 'open';
            const itemResponsible = item.Responsible || '';
            const testName = (item.Test || '').toLowerCase();
            const testDesc = (item.Description || '').toLowerCase();

            const statusMatch = status === 'all' || itemStatus === status;
            const responsibleMatch = responsible === 'all' || itemResponsible === responsible;
            const searchMatch = searchTerm === '' || testName.includes(searchTerm) || testDesc.includes(searchTerm);

            return statusMatch && responsibleMatch && searchMatch;
        });
    }
});
