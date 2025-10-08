document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    console.log("Gantt Chart script initialized.");

    const storageKey = 'Test Plan';
    const ganttChartContainer = document.getElementById('gantt-chart');

    if (!ganttChartContainer) {
        console.error("Critical Error: The Gantt chart container '#gantt-chart' was not found in the DOM.");
        return;
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
        // --- DIAGNOSTIC LOG 1 ---
        console.log(`Successfully loaded ${testPlanData.length} raw items from localStorage.`, testPlanData);
    } catch (e) {
        console.error("Failed to parse Test Plan data from localStorage.", e);
        ganttChartContainer.innerHTML = `<div class="alert alert-danger">Error parsing data. Please re-upload your file.</div>`;
        return;
    }

    const tasks = testPlanData
        .map((item, index) => {
            const startDate = parseAndFormatDate(item['Start Date']);
            const endDate = parseAndFormatDate(item['Due Date']);
            
            if (!startDate || !endDate) {
                // --- DIAGNOSTIC LOG 2 ---
                console.warn(`Skipping item #${index} due to invalid or missing dates.`, item);
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

    // --- DIAGNOSTIC LOG 3 ---
    console.log(`Processing complete. Found ${tasks.length} valid tasks to render.`, tasks);

    if (tasks.length === 0) {
        // --- IMPROVED USER MESSAGE ---
        ganttChartContainer.innerHTML = `<div class="alert alert-info p-4">
            <h4>No Tasks to Display</h4>
            <p>The Gantt chart could not be rendered because no tasks with a valid <strong>Start Date</strong> and <strong>Due Date</strong> were found in the uploaded data.</p>
            <p class="mb-0">Please check your Excel file to ensure these columns exist and contain valid dates for each task you wish to display.</p>
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
        console.log("Gantt chart successfully initialized and rendered.");
    } catch (e) {
        console.error("An error occurred during Gantt chart initialization:", e);
        ganttChartContainer.innerHTML = `<div class="alert alert-danger">A critical error occurred while trying to draw the chart. Please check the console for details.</div>`;
    }
});
