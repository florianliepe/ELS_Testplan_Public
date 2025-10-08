(function() {
    'use strict';

    if (typeof bootstrap === 'undefined' || typeof Chart === 'undefined') {
        console.error('Dependencies (Bootstrap or Chart.js) are not loaded.');
        return;
    }

    document.addEventListener('DOMContentLoaded', () => {
        let prepTasksData = [];
        let prepTaskModal;
        let prepStatusChartInstance = null;
        let prepProgressChartInstance = null;

        console.log("Prep Tasks script loaded. Initializing...");

        const modalElement = document.getElementById('prepTaskModal');
        if (modalElement) {
            prepTaskModal = new bootstrap.Modal(modalElement);
        }

        loadDataAndRender();

        document.getElementById('add-new-task-btn')?.addEventListener('click', showModalForAdd);
        document.getElementById('save-prep-task-btn')?.addEventListener('click', handleFormSave);

        function loadDataAndRender() {
            const storedData = localStorage.getItem('Preparation Tasks');
            prepTasksData = storedData ? JSON.parse(storedData) : [];
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

            if (prepStatusChartInstance) {
                prepStatusChartInstance.data.labels = Object.keys(statusCounts);
                prepStatusChartInstance.data.datasets[0].data = Object.values(statusCounts);
                prepStatusChartInstance.update();
            } else {
                prepStatusChartInstance = new Chart(statusChartCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(statusCounts),
                        datasets: [{ data: Object.values(statusCounts), backgroundColor: ['#198754', '#dc3545', '#ffc107', '#6c757d', '#0d6efd'] }]
                    },
                    options: { responsive: true, maintainAspectRatio: false }
                });
            }
            
            const overallProgress = data.length > 0 ? data.reduce((sum, item) => sum + (Number(item.Progress) || 0), 0) / data.length : 0;

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
                let statusClass = { 'completed': 'text-success', 'in_progress': 'text-primary', 'overdue': 'text-warning', 'blocked': 'text-danger' }[status] || 'text-secondary';
                
                // ========================================================
                // UPDATED: Logic to determine progress bar color
                // ========================================================
                let progressColorClass = '';
                if (progress <= 30) {
                    progressColorClass = 'bg-progress-orange'; // Custom Orange for 0-30%
                } else if (progress <= 60) {
                    progressColorClass = 'bg-warning';      // Bootstrap Yellow for 31-60%
                } else if (progress < 100) {
                    progressColorClass = 'bg-success-light';  // Custom Light Green for 61-99%
                } else {
                    progressColorClass = 'bg-success';        // Bootstrap Dark Green for 100%
                }
                
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${item['Activity Title'] || ''}</td>
                    <td>${item.Description || ''}</td>
                    <td>${item['Due Date'] || ''}</td>
                    <td class="${statusClass}"><strong>${item.Status || 'N/A'}</strong></td>
                    <td>
                        <div class="progress" style="height: 20px;">
                            <div class="progress-bar ${progressColorClass}" role="progressbar" style="width: ${progress}%;" aria-valuenow="${progress}">${progress}%</div>
                        </div>
                    </td>
                    <td>${item.Responsible || ''}</td>
                    <td>${item.Blocker || 'None'}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary edit-btn" data-index="${index}"><i class="bi bi-pencil"></i></button> 
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-index="${index}"><i class="bi bi-trash"></i></button>
                    </td>`;
                tableBody.appendChild(row);
            });

            tableBody.querySelectorAll('.edit-btn').forEach(button => button.addEventListener('click', (e) => showModalForEdit(e.currentTarget.dataset.index)));
            tableBody.querySelectorAll('.delete-btn').forEach(button => button.addEventListener('click', (e) => handleDelete(e.currentTarget.dataset.index)));
        }

        function showModalForAdd() {
            const form = document.getElementById('prep-task-form');
            if (!form || !prepTaskModal) return;
            form.reset();
            document.getElementById('modal-task-index').value = '';
            document.getElementById('prepTaskModalLabel').textContent = 'Add New Task';
            prepTaskModal.show();
        }

        function showModalForEdit(index) {
            const form = document.getElementById('prep-task-form');
            if (!form || !prepTaskModal) return;
            const item = prepTasksData[index];
            if (!item) return;

            form.reset();
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
