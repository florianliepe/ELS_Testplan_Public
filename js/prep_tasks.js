(function() {
    'use strict';

    // Check for dependencies
    if (typeof bootstrap === 'undefined') {
        console.error('Bootstrap is not loaded. The page will not function correctly.');
        return;
    }
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded. Charts will not be displayed.');
        return;
    }

    document.addEventListener('DOMContentLoaded', () => {
        // --- VARIABLES WITHIN SCOPE ---
        let prepTasksData = [];
        let prepTaskModal;
        let prepStatusChartInstance = null;
        let prepProgressChartInstance = null;

        // --- INITIALIZATION ---
        console.log("Prep Tasks script loaded. Initializing...");

        const modalElement = document.getElementById('prepTaskModal');
        if (modalElement) {
            prepTaskModal = new bootstrap.Modal(modalElement);
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
                try {
                    prepTasksData = JSON.parse(storedData);
                } catch (e) {
                    console.error("Failed to parse data from localStorage.", e);
                    prepTasksData = [];
                }
            } else {
                console.warn(`No data found in localStorage for key "${storageKey}".`);
                prepTasksData = [];
            }
            
            renderDashboard();
        }

        function renderDashboard() {
            console.log("Rendering dashboard...");
            populateSummaryCards(prepTasksData);
            updateCharts(prepTasksData);
            populateTable(prepTasksData);
        }

        function saveDataAndReRender() {
            localStorage.setItem('Preparation Tasks', JSON.stringify(prepTasksData));
            renderDashboard();
        }

        function updateCharts(data) {
            const statusChartCanvas = document.getElementById('prep-status-chart');
            const progressChartCanvas = document.getElementById('prep-progress-chart');
            if (!statusChartCanvas || !progressChartCanvas) return;

            const statusCounts = data.reduce((acc, item) => {
                const status = (item.Status || 'unknown').toLowerCase();
                acc[status] = (acc[status] || 0) + 1;
                return acc;
            }, {});
            const overallProgress = data.length > 0 ? data.reduce((sum, item) => sum + (Number(item.Progress) || 0), 0) / data.length : 0;

            if (prepStatusChartInstance) {
                prepStatusChartInstance.data.labels = Object.keys(statusCounts);
                prepStatusChartInstance.data.datasets[0].data = Object.values(statusCounts);
                prepStatusChartInstance.update();
            } else {
                prepStatusChartInstance = new Chart(statusChartCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(statusCounts),
                        datasets: [{ data: Object.values(statusCounts), backgroundColor: ['#0d6efd', '#198754', '#dc3545', '#ffc107', '#6c757d', '#fd7e14'] }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top' } } }
                });
            }

            if (prepProgressChartInstance) {
                prepProgressChartInstance.data.datasets[0].data = [overallProgress];
                prepProgressChartInstance.update();
            } else {
                prepProgressChartInstance = new Chart(progressChartCanvas, {
                    type: 'bar',
                    data: {
                        labels: ['Overall Progress'],
                        datasets: [{ label: 'Progress %', data: [overallProgress], backgroundColor: ['#0d6efd'], borderRadius: 4 }]
                    },
                    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, scales: { x: { beginAtZero: true, max: 100 } }, plugins: { legend: { display: false } } }
                });
            }
        }

        function populateSummaryCards(data) {
            document.getElementById('total-tasks').textContent = data.length;
            document.getElementById('completed-tasks').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'completed').length;
            document.getElementById('in-progress-tasks').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'in_progress').length;
            document.getElementById('blocked-tasks').textContent = data.filter(item => item.Status && item.Status.toLowerCase() === 'blocked').length;
        }

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

                // ========================================================
                // NEW: LOGIC TO DETERMINE PROGRESS BAR COLOR
                // ========================================================
                let progressColorClass = '';
                if (progress <= 30) {
                    progressColorClass = 'bg-warning'; // Orange
                } else if (progress <= 60) {
                    progressColorClass = 'bg-info'; // Yellow (using Bootstrap's light blue for contrast)
                } else if (progress < 100) {
                    progressColorClass = 'bg-success-light'; // Light Green (custom class)
                } else {
                    progressColorClass = 'bg-success'; // Dark Green for 100%
                }
                
                // ========================================================
                // UPDATED: The progress bar div now includes the dynamic color class
                // ========================================================
                const row = `<tr><td>${item['Activity Title'] || ''}</td><td>${item.Description || ''}</td><td>${item['Due Date'] || ''}</td><td class="${statusClass}"><strong>${item.Status || 'N/A'}</strong></td><td><div class="progress" style="height: 20px;"><div class="progress-bar ${progressColorClass}" role="progressbar" style="width: ${progress}%;" aria-valuenow="${progress}">${progress}%</div></div></td><td>${item.Responsible || ''}</td><td>${item.Blocker || 'None'}</td><td><button class="btn btn-sm btn-outline-primary edit-btn" data-index="${index}"><i class="bi bi-pencil"></i></button> <button class="btn btn-sm btn-outline-danger delete-btn" data-index="${index}"><i class="bi bi-trash"></i></button></td></tr>`;
                tableBody.innerHTML += row;
            });

            tableBody.querySelectorAll('.edit-btn').forEach(button => button.addEventListener('click', (e) => showModalForEdit(e.currentTarget.dataset.index)));
            tableBody.querySelectorAll('.delete-btn').forEach(button => button.addEventListener('click', (e) => handleDelete(e.currentTarget.dataset.index)));
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
})();
