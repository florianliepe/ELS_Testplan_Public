document.addEventListener('DOMContentLoaded', () => {
    // --- GLOBAL VARIABLES ---
    let prepTasksData = [];
    let prepTaskModal;

    // --- INITIALIZATION ---
    console.log("Prep Tasks script loaded. Initializing...");

    const modalElement = document.getElementById('prepTaskModal');
    if (modalElement) {
        try {
            prepTaskModal = new bootstrap.Modal(modalElement);
        } catch (e) {
            console.error("Failed to initialize Bootstrap modal.", e);
            return;
        }
    }

    loadDataAndRender();

    // --- EVENT LISTENERS ---
    const addTaskBtn = document.getElementById('add-new-task-btn');
    if (addTaskBtn) {
        addTaskBtn.addEventListener('click', showModalForAdd);
    }

    const saveBtn = document.getElementById('save-prep-task-btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', handleFormSave);
    }

    // --- CORE FUNCTIONS ---
    function loadDataAndRender() {
        const storageKey = 'Preparation Tasks';
        const storedData = localStorage.getItem(storageKey);
        
        if (storedData) {
            prepTasksData = JSON.parse(storedData);
        } else {
            console.error(`No data found in localStorage for key "${storageKey}".`);
            const tableBody = document.getElementById('prep-tasks-table-body');
            if (tableBody) {
                tableBody.innerHTML = `<tr><td colspan="8" class="text-center"><strong>Error:</strong> Data not found. Ensure the Excel sheet is named exactly "Preparation Tasks" and <a href="index.html">re-upload the file</a>.</td></tr>`;
            }
            return;
        }
        
        renderDashboard();
    }

    function renderDashboard() {
        console.log("Rendering dashboard with overview...");
        // --- UPDATED: Call all rendering functions ---
        populateSummaryCards(prepTasksData);
        createCharts(prepTasksData);
        populateTable(prepTasksData);
    }

    function saveDataAndReRender() {
        localStorage.setItem('Preparation Tasks', JSON.stringify(prepTasksData));
        renderDashboard();
    }

    // --- NEW: OVERVIEW FUNCTIONS (Copied and adapted from dashboard.js) ---

    function populateSummaryCards(data) {
        document.getElementById('total-tasks').textContent = data.length;
        document.getElementById('completed-tasks').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'completed').length;
        document.getElementById('in-progress-tasks').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'in_progress').length;
        document.getElementById('blocked-tasks').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'blocked').length;
    }

    function createCharts(data) {
        const statusChartCanvas = document.getElementById('prep-status-chart');
        const progressChartCanvas = document.getElementById('prep-progress-chart');
        if (!statusChartCanvas || !progressChartCanvas) {
            console.warn('Chart canvas elements not found.');
            return;
        }

        // Destroy existing charts to prevent conflicts on re-render
        if (window.prepStatusChartInstance) window.prepStatusChartInstance.destroy();
        if (window.prepProgressChartInstance) window.prepProgressChartInstance.destroy();

        const statusCounts = data.reduce((acc, item) => {
            const status = (item.Status || 'unknown').toLowerCase();
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        window.prepStatusChartInstance = new Chart(statusChartCanvas, {
            type: 'doughnut',
            data: {
                labels: Object.keys(statusCounts),
                datasets: [{ data: Object.values(statusCounts), backgroundColor: ['#0d6efd', '#198754', '#dc3545', '#ffc107', '#6c757d'] }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top' } } }
        });

        const overallProgress = data.length > 0 ? data.reduce((sum, item) => sum + (Number(item.Progress) || 0), 0) / data.length : 0;
        window.prepProgressChartInstance = new Chart(progressChartCanvas, {
            type: 'bar',
            data: {
                labels: ['Overall Progress'],
                datasets: [{ label: 'Progress %', data: [overallProgress], backgroundColor: ['#0d6efd'], borderRadius: 4 }]
            },
            options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, scales: { x: { beginAtZero: true, max: 100 } }, plugins: { legend: { display: false } } }
        });
    }

    // --- TABLE AND MODAL FUNCTIONS (Unchanged) ---

    function populateTable(data) {
        const tableBody = document.getElementById('prep-tasks-table-body');
        if (!tableBody) return;
        tableBody.innerHTML = '';

        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="8" class="text-center">No tasks to display.</td></tr>';
            return;
        }

        data.forEach((item, index) => {
            const progress = Number(item.Progress) || 0;
            const status = (item.Status || '').toLowerCase();
            let statusClass = '';
            switch (status) {
                case 'completed': statusClass = 'text-success'; break;
                case 'in_progress': statusClass = 'text-primary'; break;
                case 'overdue': statusClass = 'text-warning'; break;
                case 'blocked': statusClass = 'text-danger'; break;
                default: statusClass = 'text-secondary';
            }
            
            const row = `
                <tr>
                    <td>${item['Activity Title'] || ''}</td>
                    <td>${item.Description || ''}</td>
                    <td>${item['Due Date'] || ''}</td>
                    <td class="${statusClass}"><strong>${item.Status || 'N/A'}</strong></td>
                    <td>
                        <div class="progress" style="height: 20px;"><div class="progress-bar" role="progressbar" style="width: ${progress}%;" aria-valuenow="${progress}">${progress}%</div></div>
                    </td>
                    <td>${item.Responsible || ''}</td>
                    <td>${item.Blocker || 'None'}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary edit-btn" data-index="${index}"><i class="bi bi-pencil"></i></button>
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-index="${index}"><i class="bi bi-trash"></i></button>
                    </td>
                </tr>`;
            tableBody.innerHTML += row;
        });

        document.querySelectorAll('.edit-btn').forEach(button => {
            button.addEventListener('click', (e) => showModalForEdit(e.currentTarget.getAttribute('data-index')));
        });

        document.querySelectorAll('.delete-btn').forEach(button => {
            button.addEventListener('click', (e) => handleDelete(e.currentTarget.getAttribute('data-index')));
        });
    }

    function showModalForAdd() {
        if (!prepTaskModal) return;
        document.getElementById('prep-task-form').reset();
        document.getElementById('modal-task-index').value = '';
        document.getElementById('prepTaskModalLabel').textContent = 'Add New Task';
        prepTaskModal.show();
    }

    function showModalForEdit(index) {
        if (!prepTaskModal) return;
        const item = prepTasksData[index];
        if (!item) return;

        document.getElementById('prep-task-form').reset();
        document.getElementById('modal-task-index').value = index;
        document.getElementById('prepTaskModalLabel').textContent = 'Edit Task';

        document.getElementById('modal-activity-title').value = item['Activity Title'] || '';
        document.getElementById('modal-task-description').value = item.Description || '';
        document.getElementById('modal-due-date').value = item['Due Date'] || '';
        document.getElementById('modal-status').value = (item.Status || '').toLowerCase();
        document.getElementById('modal-progress').value = item.Progress || 0;
        document.getElementById('modal-responsible').value = item.Responsible || '';
        document.getElementById('modal-blocker').value = item.Blocker || '';

        prepTaskModal.show();
    }

    function handleFormSave() {
        const index = document.getElementById('modal-task-index').value;
        const taskData = {
            'Activity Title': document.getElementById('modal-activity-title').value,
            'Description': document.getElementById('modal-task-description').value,
            'Due Date': document.getElementById('modal-due-date').value,
            'Status': document.getElementById('modal-status').value,
            'Progress': document.getElementById('modal-progress').value,
            'Responsible': document.getElementById('modal-responsible').value,
            'Blocker': document.getElementById('modal-blocker').value,
        };

        if (index === '') {
            prepTasksData.push(taskData);
        } else {
            prepTasksData[parseInt(index)] = taskData;
        }

        saveDataAndReRender();
        prepTaskModal.hide();
    }

    function handleDelete(index) {
        const item = prepTasksData[index];
        if (confirm(`Are you sure you want to delete the task "${item['Activity Title']}"?`)) {
            prepTasksData.splice(index, 1);
            saveDataAndReRender();
        }
    }
});
