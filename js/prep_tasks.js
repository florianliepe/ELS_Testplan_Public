document.addEventListener('DOMContentLoaded', () => {
    // --- GLOBAL VARIABLES ---
    let testPlanData = []; // Use a global variable to hold the data
    let testPlanModal; // Variable to hold the Bootstrap Modal instance

    // --- INITIALIZATION ---
    // Initialize the Bootstrap modal
    const modalElement = document.getElementById('testPlanModal');
    if (modalElement) {
        testPlanModal = new bootstrap.Modal(modalElement);
    }

    loadDataAndRender();

    // --- NEW: EVENT LISTENERS FOR MODAL AND ACTIONS ---
    const addTestBtn = document.getElementById('add-test-btn');
    if (addTestBtn) {
        addTestBtn.addEventListener('click', showModalForAdd);
    }

    const saveBtn = document.getElementById('save-test-plan-btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', handleFormSave);
    }

    // --- CORE FUNCTIONS ---
    function loadDataAndRender() {
        // Load from localStorage instead of sessionStorage
        const storedData = localStorage.getItem('Test Plan');
        testPlanData = storedData ? JSON.parse(storedData) : [];

        if (testPlanData.length === 0) {
            console.warn("No test plan data found in localStorage. Dashboard will be empty.");
            const tableBody = document.getElementById('test-plan-table-body');
            if (tableBody) {
                tableBody.innerHTML = '<tr><td colspan="10" class="text-center">No data found. Please <a href="index.html">upload a file</a> first.</td></tr>';
            }
            return;
        }
        renderDashboard();
    }

    function renderDashboard() {
        populateSummaryCards(testPlanData);
        createCharts(testPlanData);
        populateTable(testPlanData);
        populateFilterDropdowns(testPlanData);
        addFilterEventListeners();
    }

    function saveDataAndReRender() {
        localStorage.setItem('Test Plan', JSON.stringify(testPlanData));
        renderDashboard();
    }

    function populateTable(data) {
        const tableBody = document.getElementById('test-plan-table-body');
        if (!tableBody) return;
        tableBody.innerHTML = '';

        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="10" class="text-center">No tests match the current filters.</td></tr>';
            return;
        }

        data.forEach((item, index) => {
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
            // NEW: Added data-index attribute to buttons
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
                        <button class="btn btn-sm btn-outline-primary edit-btn" data-index="${index}"><i class="bi bi-pencil"></i></button>
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-index="${index}"><i class="bi bi-trash"></i></button>
                    </td>
                </tr>`;
            tableBody.innerHTML += row;
        });

        // NEW: Add event listeners for the new edit and delete buttons
        document.querySelectorAll('.edit-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                const index = e.currentTarget.getAttribute('data-index');
                showModalForEdit(index);
            });
        });

        document.querySelectorAll('.delete-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                const index = e.currentTarget.getAttribute('data-index');
                handleDelete(index);
            });
        });
    }

    // --- NEW: MODAL AND CRUD FUNCTIONS ---

    function showModalForAdd() {
        document.getElementById('test-plan-form').reset();
        document.getElementById('modal-test-index').value = ''; // Ensure index is empty for adds
        document.getElementById('testPlanModalLabel').textContent = 'Add New Test';
        testPlanModal.show();
    }

    function showModalForEdit(index) {
        const item = testPlanData[index];
        if (!item) return;

        document.getElementById('test-plan-form').reset();
        document.getElementById('modal-test-index').value = index;
        document.getElementById('testPlanModalLabel').textContent = 'Edit Test';

        // Populate form
        document.getElementById('modal-test-name').value = item.Test || '';
        document.getElementById('modal-test-description').value = item.Description || '';
        document.getElementById('modal-start-date').value = item['Start Date'] || '';
        document.getElementById('modal-due-date').value = item['Due Date'] || '';
        document.getElementById('modal-status').value = (item.Status || '').toLowerCase();
        document.getElementById('modal-progress').value = item.Progress || 0;
        document.getElementById('modal-responsible').value = item.Responsible || '';
        document.getElementById('modal-location').value = item.Location || '';
        document.getElementById('modal-blocker').value = item.Blocker || '';

        testPlanModal.show();
    }

    function handleFormSave() {
        const index = document.getElementById('modal-test-index').value;
        const testData = {
            'Test': document.getElementById('modal-test-name').value,
            'Description': document.getElementById('modal-test-description').value,
            'Start Date': document.getElementById('modal-start-date').value,
            'Due Date': document.getElementById('modal-due-date').value,
            'Status': document.getElementById('modal-status').value,
            'Progress': document.getElementById('modal-progress').value,
            'Responsible': document.getElementById('modal-responsible').value,
            'Location': document.getElementById('modal-location').value,
            'Blocker': document.getElementById('modal-blocker').value,
        };

        if (index === '') { // Add new
            testPlanData.push(testData);
        } else { // Update existing
            testPlanData[parseInt(index)] = testData;
        }

        saveDataAndReRender();
        testPlanModal.hide();
    }

    function handleDelete(index) {
        const item = testPlanData[index];
        // Best Practice: Confirmation dialog
        if (confirm(`Are you sure you want to delete the test "${item.Test}"?`)) {
            testPlanData.splice(index, 1); // Remove the item from the array
            saveDataAndReRender();
        }
    }

    // --- UNCHANGED HELPER FUNCTIONS (populateSummaryCards, createCharts, etc.) ---
    // These functions remain the same as before, so I've included them for completeness.

    function populateSummaryCards(data) {
        document.getElementById('total-tests').textContent = data.length;
        document.getElementById('completed-tests').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'completed').length;
        document.getElementById('in-progress-tests').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'in_progress').length;
        document.getElementById('blocked-tests').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'blocked').length;
    }

    function createCharts(data) {
        const statusChartCanvas = document.getElementById('status-chart');
        const progressChartCanvas = document.getElementById('progress-chart');
        if (!statusChartCanvas || !progressChartCanvas) return;

        // Destroy existing charts if they exist to prevent conflicts
        if (window.statusChartInstance) window.statusChartInstance.destroy();
        if (window.progressChartInstance) window.progressChartInstance.destroy();

        const statusCounts = data.reduce((acc, item) => {
            const status = (item.Status || 'unknown').toLowerCase();
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        window.statusChartInstance = new Chart(statusChartCanvas, {
            type: 'doughnut',
            data: { labels: Object.keys(statusCounts), datasets: [{ data: Object.values(statusCounts), backgroundColor: ['#0d6efd', '#198754', '#dc3545', '#ffc107', '#6c757d'] }] },
            options: { responsive: true, plugins: { legend: { position: 'top' } } }
        });

        const overallProgress = data.length > 0 ? data.reduce((sum, item) => sum + (Number(item.Progress) || 0), 0) / data.length : 0;
        window.progressChartInstance = new Chart(progressChartCanvas, {
            type: 'bar',
            data: { labels: ['Overall Progress'], datasets: [{ label: 'Progress %', data: [overallProgress], backgroundColor: ['#0d6efd'], borderRadius: 4 }] },
            options: { indexAxis: 'y', responsive: true, scales: { x: { beginAtZero: true, max: 100 } }, plugins: { legend: { display: false } } }
        });
    }

    function populateFilterDropdowns(data) {
        const addOptions = (elementId, values) => {
            const selectElement = document.getElementById(elementId);
            if (selectElement) {
                // Clear existing options except the first one ("All...")
                while (selectElement.options.length > 1) {
                    selectElement.remove(1);
                }
                values.forEach(value => {
                    const option = document.createElement('option');
                    option.value = value;
                    option.textContent = value;
                    selectElement.appendChild(option);
                });
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
                element.removeEventListener(eventType, handler); // Prevent duplicate listeners
                element.addEventListener(eventType, handler);
            }
        };
        addListener('filter-status', 'change', applyFilters);
        addListener('filter-responsible', 'change', applyFilters);
        addListener('filter-location', 'change', applyFilters);
        addListener('search-tests', 'input', applyFilters);
    }
});
