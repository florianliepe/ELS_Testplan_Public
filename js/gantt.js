document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    const storageKey = 'Test Plan';
    const ganttChartContainer = document.getElementById('gantt-chart');

    // ===================================================================
    // NEW & IMPROVED: A function that handles both date strings AND Excel serial numbers.
    // ===================================================================
    function parseAndFormatDate(dateInput) {
        if (dateInput === null || dateInput === undefined) {
            return null;
        }

        let date;

        // Check if the input is a number (likely an Excel serial number)
        if (typeof dateInput === 'number' && dateInput > 1) {
            // Formula to convert Excel serial number to a JavaScript Date object.
            // (dateInput - 25569) converts Excel days to Unix days.
            // * 86400 * 1000 converts days to milliseconds.
            const utcMilliseconds = (dateInput - 25569) * 86400 * 1000;
            date = new Date(utcMilliseconds);
        } else {
            // Fallback for string dates
            date = new Date(dateInput);
        }

        // Check if the resulting date is valid
        if (isNaN(date.getTime())) {
            return null;
        }

        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
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

    // 2. Transform the data, now using the improved date parsing function
    const tasks = testPlanData
        .map((item, index) => {
            // UPDATED: Use the new, more robust function
            const startDate = parseAndFormatDate(item['Start Date']);
            const endDate = parseAndFormatDate(item['Due Date']);
            
            if (!startDate || !endDate) {
                return null; // This task will be filtered out
            }
            
            const status = (item.Status || 'not_started').toLowerCase().replace(/ /g, '_');
            
            return {
                id: `task_${index}`,
                name: `[${item.Responsible || 'N/A'}] - ${item.Test}`,
                start: startDate,
                end: endDate,
                progress: parseInt(item.Progress, 10) || 0,
                custom_class: `gantt-bar-${status}`
            };
        })
        .filter(task => task !== null) // Remove any tasks where date parsing failed
        .sort((a, b) => a.name.localeCompare(b.name));

    if (tasks.length === 0) {
        ganttChartContainer.innerHTML = `<div class="alert alert-info">No tasks with valid start and due dates could be processed. Please check the date columns in your Excel file.</div>`;
        return;
    }

    // 3. Initialize the Gantt Chart
    const gantt = new Gantt("#gantt-chart", tasks, {
        custom_popup_html: function(task) {
            const originalItem = testPlanData.find(item => `[${item.Responsible || 'N/A'}] - ${item.Test}` === task.name);
            const statusText = originalItem ? originalItem.Status || 'N/A' : 'N/A';
            const responsible = originalItem ? originalItem.Responsible || 'N/A' : 'N/A';

            return `
                <div class="gantt-popup-content p-2">
                    <h5>${task.name.split('] - ')[1]}</h5>
                    <p><strong>Responsible:</strong> ${responsible}</p>
                    <p><strong>Status:</strong> ${statusText}</p>
                    <p><strong>Progress:</strong> ${task.progress}%</p>
                    <p><strong>Duration:</strong> ${task._duration} day(s)</p>
                </div>
            `;
        },
        view_mode: 'Week'
    });
});
