document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    console.log("Gantt Chart script initialized. Version 2.");

    const storageKey = 'Test Plan';
    const ganttChartContainer = document.getElementById('gantt-chart');

    function getValueByKey(obj, keys) {
        for (const key of keys) {
            if (obj[key] !== undefined) {
                return obj[key];
            }
        }
        return undefined;
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
        if (!Array.isArray(testPlanData) || testPlanData.length === 0) {
            console.error("Data loaded from localStorage is not a valid array or is empty.", testPlanData);
            ganttChartContainer.innerHTML = `<div class="alert alert-warning">The uploaded data is empty or invalid. Please upload a valid Excel file.</div>`;
            return;
        }
        console.log(`Successfully loaded ${testPlanData.length} raw items. First item:`, testPlanData[0]);
    } catch (e) {
        ganttChartContainer.innerHTML = `<div class="alert alert-danger">Error parsing data. Please re-upload your file.</div>`;
        return;
    }

    const tasks = testPlanData
        .map((item, index) => {
            // --- VERBOSE LOGGING ---
            const startDateRaw = getValueByKey(item, ['Start Date', 'Start', 'StartDate', 'start_date', 'Startdatum']);
            const dueDateRaw = getValueByKey(item, ['Due Date', 'Due', 'EndDate', 'end_date', 'Due date', 'Enddatum']);
            const testName = getValueByKey(item, ['Test', 'Task', 'Activity', 'Testfall']);
            
            console.log(`Item #${index}: StartDateRaw=${startDateRaw}, DueDateRaw=${dueDateRaw}, TestName=${testName}`);

            const startDate = parseAndFormatDate(startDateRaw);
            const endDate = parseAndFormatDate(dueDateRaw);
            
            if (!startDate || !endDate || !testName) {
                console.warn(`Item #${index} is being skipped. One or more required fields are missing or invalid.`);
                return null;
            }
            
            return {
                id: `task_${index}`,
                name: `[${item.Responsible || 'N/A'}] - ${testName}`,
                start: startDate,
                end: endDate,
                progress: parseInt(getValueByKey(item, ['Progress', 'Fortschritt']), 10) || 0,
                custom_class: `gantt-bar-${(item.Status || 'not_started').toLowerCase().replace(/ /g, '_')}`
            };
        })
        .filter(task => task !== null);
    
    console.log(`Processing complete. Found ${tasks.length} valid tasks to render.`, tasks);

    if (tasks.length === 0) {
        ganttChartContainer.innerHTML = `<div class="alert alert-info p-4"><h4>No Tasks to Display</h4><p>The Gantt chart could not be rendered because no tasks with valid date and name columns were found.</p><p class="mb-0">Please ensure your Excel file has columns named similar to <strong>'Test'</strong>, <strong>'Start Date'</strong>, and <strong>'Due Date'</strong>.</p></div>`;
        return;
    }

    // Sort tasks AFTER filtering to avoid errors
    tasks.sort((a, b) => a.name.localeCompare(b.name));

    try {
        new Gantt("#gantt-chart", tasks, {
            custom_popup_html: function(task) { /* ... popup logic ... */ },
            view_mode: 'Week'
        });
        console.log("Gantt chart successfully initialized.");
    } catch (e) {
        console.error("Error during Gantt chart initialization:", e);
    }
});
