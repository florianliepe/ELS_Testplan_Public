document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    const storageKey = 'Test Plan';
    const ganttChartContainer = document.getElementById('gantt-chart');

    // 1. Load data from localStorage
    const storedData = localStorage.getItem(storageKey);
    if (!storedData) {
        ganttChartContainer.innerHTML = `<div class="alert alert-warning">No Test Plan data found. Please <a href="index.html">upload a file</a> first.</div>`;
        return;
    }

    let testPlanData = [];
    try {
        testPlanData = JSON.parse(storedData);
    } catch (e) {
        console.error("Failed to parse Test Plan data from localStorage.", e);
        ganttChartContainer.innerHTML = `<div class="alert alert-danger">Error parsing data. Please re-upload your file.</div>`;
        return;
    }

    // 2. Transform the data into the format Frappe Gantt requires
    const tasks = testPlanData
        .filter(item => item['Start Date'] && item['Due Date']) // Only include items with valid dates
        .sort((a, b) => (a.Responsible || 'Unassigned').localeCompare(b.Responsible || 'Unassigned')) // Group by Responsible
        .map((item, index) => {
            const status = (item.Status || 'not_started').toLowerCase().replace(/ /g, '_');
            
            // This is the required structure for a Frappe Gantt task
            return {
                id: `task_${index}`,
                name: `[${item.Responsible || 'N/A'}] - ${item.Test}`,
                start: item['Start Date'],
                end: item['Due Date'],
                progress: item.Progress || 0,
                // NEW: Assign a custom class based on status for coloring
                custom_class: `gantt-bar-${status}` 
            };
        });

    if (tasks.length === 0) {
        ganttChartContainer.innerHTML = `<div class="alert alert-info">No tasks with valid start and due dates were found in the data.</div>`;
        return;
    }

    // 3. Initialize the Gantt Chart
    const gantt = new Gantt("#gantt-chart", tasks, {
        // Add a custom popup on hover for more details
        custom_popup_html: function(task) {
            const originalTask = testPlanData.find(t => `[${t.Responsible || 'N/A'}] - ${t.Test}` === task.name);
            const statusText = originalTask.Status || 'Not Started';

            return `
                <div class="gantt-popup-content p-2">
                    <h5>${task.name.split('] - ')[1]}</h5>
                    <p><strong>Responsible:</strong> ${originalTask.Responsible || 'N/A'}</p>
                    <p><strong>Status:</strong> ${statusText}</p>
                    <p><strong>Progress:</strong> ${task.progress}%</p>
                    <p><strong>Duration:</strong> ${task._duration} day(s)</p>
                </div>
            `;
        },
        view_mode: 'Week' // Set the default zoom level
    });
});
