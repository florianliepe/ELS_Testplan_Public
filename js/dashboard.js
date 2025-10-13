document.addEventListener('DOMContentLoaded', () => {
    // --- GLOBAL VARIABLES ---
    let testPlanData = [];
    let testPlanModal;

    // --- INITIALIZATION ---
    const modalElement = document.getElementById('testPlanModal');
    if (modalElement) {
        testPlanModal = new bootstrap.Modal(modalElement);
    }

    loadDataAndRender();

    // --- EVENT LISTENERS ---
    document.getElementById('add-test-btn')?.addEventListener('click', showModalForAdd);
    document.getElementById('save-test-plan-btn')?.addEventListener('click', handleFormSave);

    // ===================================================================
    // NEW: Event listener for the Excel Export button
    // ===================================================================
    const exportBtn = document.getElementById('export-excel-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', handleExportToExcel);
    }
    // ===================================================================


    // --- CORE FUNCTIONS ---
    function loadDataAndRender() {
        const storedData = localStorage.getItem('Test Plan');
        testPlanData = storedData ? JSON.parse(storedData) : [];

        if (testPlanData.length === 0) {
            console.warn("No test plan data found.");
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

    // ===================================================================
    // NEW: Function to handle the export to Excel logic
    // ===================================================================
    function handleExportToExcel() {
        console.log("Export to Excel button clicked.");
        if (testPlanData.length === 0) {
            alert("There is no data to export.");
            return;
        }

        // Check if the XLSX library is loaded
        if (typeof XLSX === 'undefined') {
            console.error("XLSX library is not loaded. Cannot export to Excel.");
            alert("Error: The Excel export library is not available.");
            return;
        }

        // 1. Create a new worksheet from the JSON data
        const worksheet = XLSX.utils.json_to_sheet(testPlanData);

        // 2. Create a new workbook
        const workbook = XLSX.utils.book_new();

        // 3. Append the worksheet to the workbook
        XLSX.utils.book_append_sheet(workbook, worksheet, "Test Plan");

        // 4. Trigger the file download
        XLSX.writeFile(workbook, "Test_Plan_Export.xlsx");
    }
    // ===================================================================

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

        document.querySelectorAll('.edit-btn').forEach(button => {
            button.addEventListener('click', (e) => showModalForEdit(e.currentTarget.dataset.index));
        });

        document.querySelectorAll('.delete-btn').forEach(button => {
            button.addEventListener('click', (e) => handleDelete(e.currentTarget.dataset.index));
        });
    }

    function showModalForAdd() {
        document.getElementById('test-plan-form').reset();
        document.getElementById('modal-test-index').value = '';
        document.getElementById('testPlanModalLabel').textContent = 'Add New Test';
        testPlanModal.show();
    }

    function showModalForEdit(index) {
        const item = testPlanData[index];
        if (!item) return;
        document.getElementById('test-plan-form').reset();
        document.getElementById('modal-test-index').value = index;
        document.getElementById('testPlanModalLabel').textContent = 'Edit Test';
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

        if (index === '') {
            testPlanData.push(testData);
        } else {
            testPlanData[parseInt(index)] = testData;
        }
        saveDataAndReRender();
        testPlanModal.hide();
    }

    function handleDelete(index) {
        const item = testPlanData[index];
        if (confirm(`Are you sure you want to delete the test "${item.Test}"?`)) {
            testPlanData.splice(index, 1);
            saveDataAndReRender();
        }
    }

    function populateSummaryCards(data) { /* ... (unchanged) ... */ }
    function createCharts(data) { /* ... (unchanged) ... */ }
    function populateFilterDropdowns(data) { /* ... (unchanged) ... */ }
    function applyFilters() { /* ... (unchanged) ... */ }
    function addFilterEventListeners() { /* ... (unchanged) ... */ }
});
