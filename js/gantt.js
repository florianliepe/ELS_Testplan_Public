document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    const storageKey = 'Test Plan';
    const ganttChartContainer = document.getElementById('gantt-chart');

    // ===================================================================
    // NEW: A robust function to parse and format dates
    // This will accept various date formats and return 'YYYY-MM-DD'
    // ===================================================================
    function formatDate(dateInput) {
        if (!dateInput) return null;

        const date = new Date(dateInput);

        // Check if the date is valid
        if (isNaN(date.getTime())) {
            return null;
        }

        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
        const day = String(date.getDate()).padStart(2, '0');

        return `${year}-${month}-${day}`;
    }

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

    // 2. Transform the data, now using the formatDate function
    const tasks = testPlanData
        .map((item, index) => {
            // ===================================================================
            // UPDATED: Use the new function to ensure dates are correctly formatted
            // ===================================================================
            const startDate = formatDate(item['Start Date']);
            const endDate = formatDate(item['Due Date']);

            // If dates are invalid, this task will be filtered out later
            if (!startDate || !endDate) {
                return null;
            }
            
            const status = (item.Status || 'not_started').toLowerCase().replace(/ /g, '_');
            
            return {
                id: `task_${index}`,
                name: `[${item.Responsible || 'N/A'}] - ${item.Test}`,
                start: startDate, // Now guaranteed to be in 'YYYY-MM-DD' format
                end: endDate,     // Now guaranteed to be in 'YYYY-MM-DD' format
                progress: parseInt(item.Progress, 10) || 0, // Ensure progress is an integer
                custom_class: `gantt-bar-${status}`
            };
        })
        .filter(task => task !== null) // Remove any tasks with invalid dates
        .sort((a, b) => a.name.localeCompare(b.name)); // Group by Responsible

    if (tasks.length === 0) {
        ganttChartContainer.innerHTML = `<div class="alert alert-info">No tasks with valid start and due dates were found in the data.</div>`;
        return;
    }

    // 3. Initialize the Gantt Chart
    const gantt = new Gantt("#gantt-chart", tasks, {
        custom_popup_html: function(task) {
            // Find the original item to get raw data for the popup
            const originalItem = testPlanData.find(item => `[${item.Responsible || 'N/A'}] - ${item.Test}` === task.name);
            const statusText = originalItem ? originalItem.Status : 'N/A';

            return `
                <div class="gantt-popup-content p-2">
                    <h5>${task.name.split('] - ')[1]}</h5>
                    <p><strong>Responsible:</strong> ${originalItem ? originalItem.Responsible : 'N/A'}</p>
                    <p><strong>Status:</strong> ${statusText}</p>
                    <p><strong>Progress:</strong> ${task.progress}%</p>
                    <p><strong>Duration:</strong> ${task._duration} day(s)</p>
                </div>
            `;
        },
        view_mode: 'Week'
    });
});
