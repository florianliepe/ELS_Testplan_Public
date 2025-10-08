document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    const storageKey = 'Test Plan';
    const ganttChartContainer = document.getElementById('gantt-chart');

    if (!ganttChartContainer) {
        console.error("Gantt chart container '#gantt-chart' not found.");
        return;
    }

    // ===================================================================
    // NEW: Smart function to get a value from an object using multiple possible key names.
    // This makes the script robust against variations in Excel column headers.
    // ===================================================================
    function getValueByKey(obj, keys) {
        for (const key of keys) {
            if (obj[key] !== undefined) {
                return obj[key];
            }
        }
        return undefined; // Return undefined if no key is found
    }

    function parseAndFormatDate(dateInput) {
        if (dateInput === null || dateInput === undefined) return null;
        let date;
        if (typeof dateInput === 'number' && dateInput > 1) {
            const utcMilliseconds = (dateInput - 25569) * 86400 * 1000;
            date = new Date(utcMilliseconds);
        } else {
            date = new Date(dateInput);
        }
        if (isNaN(date.getTime())) return null;
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    const storedData = localStorage.getItem(storageKey);
    if (!storedData) {
        ganttChartContainer.innerHTML = `<div class="alert alert-warning">No Test Plan data found. Please <a href="index.html">upload a file</a> first.</div>`;
        return;
    }

    let testPlanData = [];
    try {
        testPlanData = JSON.parse(storedData);
    } catch (e) {
        ganttChartContainer.innerHTML = `<div class="alert alert-danger">Error parsing data. Please re-upload your file.</div>`;
        return;
    }

    const tasks = testPlanData
        .map((item, index) => {
            // ===================================================================
            // UPDATED: Use the smart getValueByKey function to find the dates.
            // ===================================================================
            const startDateRaw = getValueByKey(item, ['Start Date', 'Start', 'StartDate', 'start_date']);
            const dueDateRaw = getValueByKey(item, ['Due Date', 'Due', 'EndDate', 'end_date', 'Due date']);

            const startDate = parseAndFormatDate(startDateRaw);
            const endDate = parseAndFormatDate(dueDateRaw);
            
            if (!startDate || !endDate) {
                return null;
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
        .filter(task => task !== null)
        .sort((a, b) => a.name.localeCompare(b.name));

    if (tasks.length === 0) {
        ganttChartContainer.innerHTML = `<div class="alert alert-info p-4">
            <h4>No Tasks to Display</h4>
            <p>The Gantt chart could not be rendered because no tasks with valid date columns were found.</p>
            <p class="mb-0">Please ensure your Excel file has columns named similar to <strong>'Start Date'</strong> and <strong>'Due Date'</strong>.</p>
        </div>`;
        return;
    }

    try {
        const gantt = new Gantt("#gantt-chart", tasks, {
            custom_popup_html: function(task) {
                const originalItem = testPlanData.find(item => `[${item.Responsible || 'N/A'}] - ${item.Test}` === task.name);
                const statusText = originalItem ? originalItem.Status || 'N/A' : 'N/A';
                const responsible = originalItem ? originalItem.Responsible || 'N/A' : 'N/A';
                return `<div class="gantt-popup-content p-2"><h5>${task.name.split('] - ')[1]}</h5><p><strong>Responsible:</strong> ${responsible}</p><p><strong>Status:</strong> ${statusText}</p><p><strong>Progress:</strong> ${task.progress}%</p><p><strong>Duration:</strong> ${task._duration} day(s)</p></div>`;
            },
            view_mode: 'Week'
        });
    } catch (e) {
        ganttChartContainer.innerHTML = `<div class="alert alert-danger">A critical error occurred while trying to draw the chart.</div>`;
    }
});
