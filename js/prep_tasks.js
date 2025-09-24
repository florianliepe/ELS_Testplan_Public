document.addEventListener('DOMContentLoaded', () => {
    // --- GLOBAL VARIABLES ---
    let prepTasksData = []; // Use a global variable to hold the data
    let prepTaskModal; // Variable to hold the Bootstrap Modal instance

    // --- INITIALIZATION ---
    // Initialize the Bootstrap modal
    const modalElement = document.getElementById('prepTaskModal');
    if (modalElement) {
        prepTaskModal = new bootstrap.Modal(modalElement);
    }

    loadDataAndRender();

    // --- EVENT LISTENERS FOR MODAL AND ACTIONS ---
    const addTaskBtn = document.getElementById('add-new-task-btn'); // Ensure you have a button with this ID in your HTML
    if (addTaskBtn) {
        addTaskBtn.addEventListener('click', showModalForAdd);
    }

    const saveBtn = document.getElementById('save-prep-task-btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', handleFormSave);
    }

    // --- CORE FUNCTIONS ---
    function loadDataAndRender() {
        // Load from localStorage, using the correct key for preparation tasks
        const storedData = localStorage.getItem('Preparation Tasks');
        prepTasksData = storedData ? JSON.parse(storedData) : [];

        if (prepTasksData.length === 0) {
            console.warn("No Preparation Tasks data found in localStorage. Dashboard will be empty.");
            const tableBody = document.getElementById('prep-tasks-table-body'); // Make sure your table body has this ID
            if (tableBody) {
                tableBody.innerHTML = '<tr><td colspan="8" class="text-center">No data found. Please <a href="index.html">upload a file</a> first.</td></tr>';
            }
            return;
        }
        renderDashboard();
    }

    function renderDashboard() {
        // You can add summary cards and charts here if your prep_tasks.html has them
        populateTable(prepTasksData);
        // Add filter logic if needed
    }

    function saveDataAndReRender() {
        localStorage.setItem('Preparation Tasks', JSON.stringify(prepTasksData));
        renderDashboard();
    }

    function populateTable(data) {
        const tableBody = document.getElementById('prep-tasks-table-body'); // Make sure your table body has this ID
        if (!tableBody) return;
        tableBody.innerHTML = '';

        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="8" class="text-center">No tasks match the current filters.</td></tr>';
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

        // Add event listeners for the new edit and delete buttons
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

    // --- MODAL AND CRUD FUNCTIONS ---

    function showModalForAdd() {
        document.getElementById('prep-task-form').reset();
        document.getElementById('modal-task-index').value = '';
        document.getElementById('prepTaskModalLabel').textContent = 'Add New Task';
        prepTaskModal.show();
    }

    function showModalForEdit(index) {
        const item = prepTasksData[index];
        if (!item) return;

        document.getElementById('prep-task-form').reset();
        document.getElementById('modal-task-index').value = index;
        document.getElementById('prepTaskModalLabel').textContent = 'Edit Task';

        // Populate form
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

        if (index === '') { // Add new
            prepTasksData.push(taskData);
        } else { // Update existing
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
