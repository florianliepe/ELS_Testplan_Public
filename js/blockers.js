document.addEventListener('DOMContentLoaded', function() {
    'use strict';

    // --- MODULE-SCOPED VARIABLES ---
    let allBlockers = [];
    let blockerModal;
    let statusPieChartInstance = null;
    const storageKey = 'Blockers';

    // --- INITIALIZATION ---
    function initialize() {
        const modalElement = document.getElementById('blockerModal');
        if (modalElement) {
            blockerModal = new bootstrap.Modal(modalElement);
        }
        
        loadDataAndRender();
        addEventListeners();
    }

    // --- DATA HANDLING ---
    function loadDataAndRender() {
        // FIX: Load from localStorage instead of sessionStorage
        const storedData = localStorage.getItem(storageKey);
        
        if (!storedData) {
            console.warn('No blocker data found in localStorage. Redirecting to upload page.');
            // Redirect if no data exists, which is the correct behavior
            window.location.href = 'index.html';
            return;
        }

        try {
            allBlockers = JSON.parse(storedData);
        } catch (e) {
            console.error("Failed to parse blocker data from localStorage.", e);
            allBlockers = [];
        }
        
        renderDashboard();
    }
    
    function saveDataAndReRender() {
        localStorage.setItem(storageKey, JSON.stringify(allBlockers));
        renderDashboard();
    }

    // --- RENDERING FUNCTIONS ---
    function renderDashboard() {
        renderSummary(allBlockers);
        renderPieChart(allBlockers);
        renderTable(allBlockers);
    }
    
    function renderSummary(data) {
        const statusCounts = data.reduce((acc, item) => {
            const status = (item['Resolution Status'] || 'open').toLowerCase();
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, { open: 0, in_progress: 0, resolved: 0 });

        document.getElementById('total-blockers').textContent = data.length;
        document.getElementById('open-blockers').textContent = statusCounts.open;
        document.getElementById('inprogress-blockers').textContent = statusCounts.in_progress;
        document.getElementById('resolved-blockers').textContent = statusCounts.resolved;
    }

    function renderPieChart(data) {
        const ctx = document.getElementById('status-pie-chart')?.getContext('2d');
        if (!ctx) return;

        const statusCounts = data.reduce((acc, item) => {
            const status = (item['Resolution Status'] || 'open').toLowerCase();
            acc[status] = (acc[status] || 0) + 1;
            return acc;
        }, {});

        const labels = Object.keys(statusCounts);
        const chartData = Object.values(statusCounts);
        const backgroundColors = labels.map(label => {
            if (label === 'open') return '#dc3545';
            if (label === 'in_progress') return '#ffc107';
            if (label === 'resolved') return '#198754';
            return '#6c757d';
        });

        if (statusPieChartInstance) {
            statusPieChartInstance.destroy();
        }

        statusPieChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels.map(l => l.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase())),
                datasets: [{ data: chartData, backgroundColor: backgroundColors, borderWidth: 1 }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }

    function renderTable(data) {
        const tableBody = document.getElementById('blockers-table-body');
        if (!tableBody) return;
        tableBody.innerHTML = '';

        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="7" class="text-center">No blockers found.</td></tr>';
            return;
        }

        data.forEach((item, index) => {
            const status = (item['Resolution Status'] || 'open').toLowerCase();
            const priority = (item.Priority || 'low').toLowerCase();
            
            const row = `
                <tr>
                    <td>${item['Blocker Name'] || ''}</td>
                    <td>${item.Description || ''}</td>
                    <td>${item.Responsible || ''}</td>
                    <td>${item['Start Date'] || ''}</td>
                    <td><span class="badge bg-${priority === 'high' ? 'danger' : (priority === 'medium' ? 'warning text-dark' : 'primary')}">${priority}</span></td>
                    <td><span class="badge bg-${status === 'open' ? 'danger' : (status === 'in_progress' ? 'warning text-dark' : 'success')}">${status.replace('_', ' ')}</span></td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary edit-btn" data-index="${index}"><i class="bi bi-pencil"></i></button>
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-index="${index}"><i class="bi bi-trash"></i></button>
                    </td>
                </tr>`;
            tableBody.innerHTML += row;
        });
    }

    // --- EVENT HANDLING ---
    function addEventListeners() {
        document.getElementById('add-blocker-btn')?.addEventListener('click', showModalForAdd);
        document.getElementById('save-blocker-btn')?.addEventListener('click', handleFormSave);
        
        // Use event delegation for edit/delete buttons
        document.getElementById('blockers-table-body')?.addEventListener('click', function(e) {
            const target = e.target.closest('button');
            if (!target) return;

            const index = target.dataset.index;
            if (target.classList.contains('edit-btn')) {
                showModalForEdit(index);
            } else if (target.classList.contains('delete-btn')) {
                handleDelete(index);
            }
        });
    }

    // --- MODAL AND CRUD LOGIC ---
    function showModalForAdd() {
        document.getElementById('blocker-form').reset();
        document.getElementById('modal-blocker-index').value = '';
        document.getElementById('blockerModalLabel').textContent = 'Add New Blocker';
        blockerModal.show();
    }

    function showModalForEdit(index) {
        const item = allBlockers[index];
        if (!item) return;

        document.getElementById('blocker-form').reset();
        document.getElementById('modal-blocker-index').value = index;
        document.getElementById('blockerModalLabel').textContent = 'Edit Blocker';
        
        document.getElementById('modal-blocker-name').value = item['Blocker Name'] || '';
        document.getElementById('modal-description').value = item.Description || '';
        document.getElementById('modal-responsible').value = item.Responsible || '';
        document.getElementById('modal-start-date').value = item['Start Date'] || '';
        document.getElementById('modal-priority').value = (item.Priority || 'low').toLowerCase();
        document.getElementById('modal-status').value = (item['Resolution Status'] || 'open').toLowerCase();

        blockerModal.show();
    }

    function handleFormSave() {
        const index = document.getElementById('modal-blocker-index').value;
        const blockerData = {
            'Blocker Name': document.getElementById('modal-blocker-name').value,
            'Description': document.getElementById('modal-description').value,
            'Responsible': document.getElementById('modal-responsible').value,
            'Start Date': document.getElementById('modal-start-date').value,
            'Priority': document.getElementById('modal-priority').value,
            'Resolution Status': document.getElementById('modal-status').value,
        };

        if (index === '') { // Add new
            allBlockers.push(blockerData);
        } else { // Update existing
            allBlockers[parseInt(index)] = blockerData;
        }

        saveDataAndReRender();
        blockerModal.hide();
    }

    function handleDelete(index) {
        const item = allBlockers[index];
        if (confirm(`Are you sure you want to delete the blocker "${item['Blocker Name']}"?`)) {
            allBlockers.splice(index, 1);
            saveDataAndReRender();
        }
    }

    // --- START THE APPLICATION ---
    initialize();
});
