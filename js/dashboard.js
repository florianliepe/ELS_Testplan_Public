document.addEventListener('DOMContentLoaded', () => {
    // --- DATA RETRIEVAL ---
    const testPlanData = JSON.parse(sessionStorage.getItem('Test Plan'));

    if (!testPlanData || testPlanData.length === 0) {
        console.warn("No test plan data found in sessionStorage. Dashboard will be empty.");
        document.getElementById('test-plan-table-body').innerHTML = '<tr><td colspan="10" class="text-center">No data found. Please <a href="index.html">upload a file</a> first.</td></tr>';
        return;
    }

    // --- INITIALIZATION ---
    populateSummaryCards(testPlanData);
    createCharts(testPlanData);
    populateTable(testPlanData);
    populateFilterDropdowns(testPlanData); // Function that was causing the error
    addFilterEventListeners();

    // --- FUNCTIONS ---

    function populateSummaryCards(data) {
        document.getElementById('total-tests').textContent = data.length;
        document.getElementById('completed-tests').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'completed').length;
        document.getElementById('in-progress-tests').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'in_progress').length;
        document.getElementById('blocked-tests').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'blocked').length;
    }

    function createCharts(data) {
        const statusChartCanvas = document.getElementById('status-chart');
        const progressChartCanvas = document.getElementById('progress-chart');
        if (!statusChartCanvas || !progressChartCanvas) {
            console.warn('Chart canvas elements not found.');
            return;
        }

        const statusCounts = data.reduce((acc, item) => {
            const status = (item.Status || 'unknown').toLowerCase();
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        new Chart(statusChartCanvas, {
            type: 'doughnut',
            data: { labels: Object.keys(statusCounts), datasets: [{ data: Object.values(statusCounts), backgroundColor: ['#0d6efd', '#198754', '#dc3545', '#ffc107', '#6c757d'] }] },
            options: { responsive: true, plugins: { legend: { position: 'top' } } }
        });

        const overallProgress = data.length > 0 ? data.reduce((sum, item) => sum + (Number(item.Progress) || 0), 0) / data.length : 0;
        new Chart(progressChartCanvas, {
            type: 'bar',
            data: { labels: ['Overall Progress'], datasets: [{ label: 'Progress %', data: [overallProgress], backgroundColor: ['#0d6efd'], borderRadius: 4 }] },
            options: { indexAxis: 'y', responsive: true, scales: { x: { beginAtZero: true, max: 100 } }, plugins: { legend: { display: false } } }
        });
    }

    function populateTable(data) {
        const tableBody = document.getElementById('test-plan-table-body');
        if (!tableBody) return;
        tableBody.innerHTML = '';

        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="10" class="text-center">No tests match the current filters.</td></tr>';
            return;
        }

        data.forEach(item => {
            const progress = Number(item.Progress) || 0;
            const status = (item.Status || '').toLowerCase();
            let statusBadge = '';
            switch (status) {
                case 'completed': statusBadge = 'bg-success'; break;
                case 'in_progress': statusBadge = 'bg-primary'; break;
                case 'overdue': statusBadge = 'bg-warning text-dark'; break;
                case 'blocked': statusBadge = 'bg-danger'; break;
                default: statusBadge = 'bg-secondary';
            }
            const row = `
                <tr>
                    <td>${item.Test || ''}</td>
                    <td>${item.Description || ''}</td>
                    <td>${item['Start Date'] || ''}</td>
                    <td>${item['Due Date'] || ''}</td>
                    <td><span class="badge ${statusBadge}">${item.Status || 'N/A'}</span></td>
                    <td>
                        <div class="progress" style="height: 20px;"><div class="progress-bar" role="progressbar" style="width: ${progress}%;" aria-valuenow="${progress}">${progress}%</div></div>
                    </td>
                    <td>${item.Responsible || ''}</td>
                    <td>${item.Location || ''}</td>
                    <td>${item.Blocker || 'None'}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary"><i class="bi bi-pencil"></i></button>
                        <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
                    </td>
                </tr>`;
            tableBody.innerHTML += row;
        });
    }
    
    // --- FIX IS APPLIED HERE ---
    function populateFilterDropdowns(data) {
        const addOptions = (elementId, values) => {
            const selectElement = document.getElementById(elementId);
            // This check prevents the "Cannot read properties of null" error
            if (selectElement) {
                values.forEach(value => {
                    const option = document.createElement('option');
                    option.value = value;
                    option.textContent = value;
                    selectElement.appendChild(option);
                });
            } else {
                console.error(`Filter element with id '${elementId}' was not found in the HTML.`);
            }
        };

        addOptions('filter-status', [...new Set(data.map(item => item.Status).filter(Boolean))]);
        addOptions('filter-responsible', [...new Set(data.map(item => item.Responsible).filter(Boolean))]);
        addOptions('filter-location', [...new Set(data.map(item => item.Location).filter(Boolean))]);
    }
    
    function applyFilters() {
        const statusFilter = document.getElementById('filter-status').value.toLowerCase();
        const responsibleFilter = document.getElementById('filter-responsible').value.toLowerCase();
        const locationFilter = document.getElementById('filter-location').value.toLowerCase();
        const searchFilter = document.getElementById('search-tests').value.toLowerCase();

        const filteredData = testPlanData.filter(item => {
            return (statusFilter === '' || (item.Status || '').toLowerCase() === statusFilter) &&
                   (responsibleFilter === '' || (item.Responsible || '').toLowerCase() === responsibleFilter) &&
                   (locationFilter === '' || (item.Location || '').toLowerCase() === locationFilter) &&
                   (searchFilter === '' || (item.Test || '').toLowerCase().includes(searchFilter) || (item.Description || '').toLowerCase().includes(searchFilter));
        });
        populateTable(filteredData);
    }

    function addFilterEventListeners() {
        const addListener = (elementId, eventType, handler) => {
            const element = document.getElementById(elementId);
            if (element) {
                element.addEventListener(eventType, handler);
            }
        };
        addListener('filter-status', 'change', applyFilters);
        addListener('filter-responsible', 'change', applyFilters);
        addListener('filter-location', 'change', applyFilters);
        addListener('search-tests', 'input', applyFilters);
    }

    // Event listener for the export button
    const exportBtn = document.getElementById('export-excel-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            if (typeof exportDataToExcel === 'function') {
                exportDataToExcel();
            } else {
                console.error('exportDataToExcel function not found. Make sure export.js is loaded.');
            }
        });
    }
});
