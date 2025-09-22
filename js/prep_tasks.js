document.addEventListener('DOMContentLoaded', function() {
    // --- CONFIGURATION ---
    const STATUS_COLORS = {
        not_started: '#95a5a6',
        in_progress: '#f1c40f',
        completed: '#2ecc71',
        blocked: '#e74c3c',
        overdue: '#c0392b',
        default: '#bdc3c7'
    };

    // --- ELEMENT REFERENCES ---
    const clearDataBtn = document.getElementById('clear-data-btn');
    const statusPieChartCtx = document.getElementById('status-pie-chart')?.getContext('2d');
    const tableBody = document.getElementById('prep-tasks-table-body');
    const statusFilter = document.getElementById('status-filter');
    const responsibleFilter = document.getElementById('responsible-filter');
    const searchFilter = document.getElementById('search-filter');

    // --- DATA LOADING AND INITIALIZATION ---
    const prepTasksJSON = sessionStorage.getItem('Preparation Tasks');
    if (!prepTasksJSON) {
        window.location.href = 'index.html';
        return;
    }
    const allPrepTasks = JSON.parse(prepTasksJSON);

    // --- MAIN EXECUTION ---
    populateFilters(allPrepTasks);
    renderPage(allPrepTasks);

    // --- EVENT LISTENERS ---
    clearDataBtn.addEventListener('click', () => {
        sessionStorage.clear();
        window.location.href = 'index.html';
    });

    [statusFilter, responsibleFilter, searchFilter].forEach(filter => {
        filter.addEventListener('input', () => {
            const filteredData = applyFilters(allPrepTasks);
            renderTable(filteredData);
        });
    });

    // --- FUNCTIONS ---

    // *** NEW FUNCTION TO HANDLE EXCEL DATE CONVERSION ***
    function formatDate(excelDate) {
        // If the date is empty, a zero, or not provided, return an empty string.
        if (!excelDate) {
            return '';
        }
        // If the date is a number (Excel's serial date format), convert it.
        if (typeof excelDate === 'number') {
            // Formula to convert Excel serial date to a JS Date object.
            const date = new Date((excelDate - 25569) * 86400 * 1000);
            const day = String(date.getDate()).padStart(2, '0');
            const month = String(date.getMonth() + 1).padStart(2, '0'); // JS months are 0-indexed
            const year = date.getFullYear();
            return `${day}.${month}.${year}`;
        }
        // If it's already a string, return it as is.
        return excelDate;
    }

    function normalizeStatus(status) {
        return status ? String(status).toLowerCase().replace(/ /g, '_') : 'not_started';
    }

    function renderPage(data) {
        renderSummary(data);
        renderPieChart(data);
        renderTable(data);
    }

    function renderSummary(data) {
        const statusCounts = data.reduce((acc, item) => {
            const status = normalizeStatus(item.Status);
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        document.getElementById('total-tasks').textContent = data.length;
        document.getElementById('completed-tasks').textContent = statusCounts.completed || 0;
        document.getElementById('inprogress-tasks').textContent = statusCounts.in_progress || 0;
        document.getElementById('blocked-tasks').textContent = statusCounts.blocked || 0;
    }

    function renderPieChart(data) {
        if (!statusPieChartCtx) return;

        const statusCounts = data.reduce((acc, item) => {
            const status = normalizeStatus(item.Status);
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
                    label: 'Task Status',
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
            tableBody.innerHTML = '<tr><td colspan="7">No matching tasks found.</td></tr>';
            return;
        }

        data.forEach(item => {
            const status = normalizeStatus(item.Status);
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${item['Activity Title'] || ''}</td>
                <td>${item.Description || ''}</td>
                <td><span class="status-badge status-${status}">${status.replace(/_/g, ' ')}</span></td>
                <td><div class="progress-bar"><div class="progress-bar-fill" style="width: ${item.Progress || 0}%;"></div></div> ${item.Progress || 0}%</td>
                <td>${item.Responsible || ''}</td>
                // *** THIS LINE IS NOW FIXED TO USE THE FORMATTING FUNCTION ***
                <td>${formatDate(item['Due Date'])}</td>
                <td>${item.Volume || ''}</td>
            `;
            tableBody.appendChild(row);
        });
    }

    function populateFilters(data) {
        const statuses = [...new Set(data.map(item => normalizeStatus(item.Status)))];
        const responsibles = [...new Set(data.map(item => item.Responsible).filter(Boolean))];

        statuses.forEach(status => {
            const option = document.createElement('option');
            option.value = status;
            option.textContent = status.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
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
            const itemStatus = normalizeStatus(item.Status);
            const itemResponsible = item.Responsible || '';
            const itemTitle = (item['Activity Title'] || '').toLowerCase();
            const itemDesc = (item.Description || '').toLowerCase();

            const statusMatch = status === 'all' || itemStatus === status;
            const responsibleMatch = responsible === 'all' || itemResponsible === responsible;
            const searchMatch = searchTerm === '' || itemTitle.includes(searchTerm) || itemDesc.includes(searchTerm);

            return statusMatch && responsibleMatch && searchMatch;
        });
    }
});
