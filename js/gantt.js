document.addEventListener('DOMContentLoaded', () => {
    'use strict';

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

    // ===================================================================
    // NEW: Specialized function to parse "DD.MM.YYYY" string dates.
    // ===================================================================
    function parseDateString(dateString) {
        if (!dateString || typeof dateString !== 'string') return null;

        // Split the string by the dot separator
        const parts = dateString.split('.');
        if (parts.length !== 3) return null;

        const day = parts[0];
        const month = parts[1];
        const year = parts[2];

        // Reassemble into ISO format (YYYY-MM-DD) required by Gantt library
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
            const startDateRaw = getValueByKey(item, ['Start Date', 'Start', 'StartDate']);
            const dueDateRaw = getValueByKey(item, ['Due Date', 'Due', 'EndDate']);
            
            // UPDATED: Use the new parsing function
            const startDate = parseDateString(startDateRaw);
            const endDate = parseDateString(dueDateRaw);
            
            if (!startDate || !endDate) {
                // Silently skip items with invalid dates
                return null;
            }
            
            const status = (item.Status || 'not_started').toLowerCase().replace(/ /g, '_');
            const testName = getValueByKey(item, ['Test', 'Task', 'Activity']) || `Task ${index}`;
            
            return {
                id: `task_${index}`,
                name: `[${item.Responsible || 'N/A'}] - ${testName}`,
                start: startDate, // Will be 'YYYY-MM-DD'
                end: endDate,     // Will be 'YYYY-MM-DD'
                progress: parseInt(getValueByKey(item, ['Progress', 'Fortschritt']), 10) || 0,
                custom_class: `gantt-bar-${status}`
            };
        })
        .filter(task => task !== null);

    if (tasks.length === 0) {
        ganttChartContainer.innerHTML = `<div class="alert alert-info p-4">
            <h4>No Tasks to Display</h4>
            <p>The Gantt chart could not be rendered because no tasks with valid dates in the format <strong>DD.MM.YYYY</strong> were found.</p>
        </div>`;
        return;
    }

    // Sort by Responsible person (extracted from name)
    tasks.sort((a, b) => a.name.localeCompare(b.name));

    try {
        new Gantt("#gantt-chart", tasks, {
            custom_popup_html: function(task) {
                // Extract info back from the generated name string
                const parts = task.name.match(/^\[(.*?)\] - (.*)$/);
                const responsible = parts ? parts[1] : 'N/A';
                const testName = parts ? parts[2] : task.name;
                // Get status from class name
                const status = task.custom_class.replace('gantt-bar-', '').replace('_', ' ');

                return `
                <div class="gantt-popup-content p-2" style="width: 250px;">
                    <h6 class="mb-2 border-bottom pb-1">${testName}</h6>
                    <div class="small">
                        <div><strong>Responsible:</strong> ${responsible}</div>
                        <div><strong>Status:</strong> <span class="text-capitalize">${status}</span></div>
                        <div><strong>Progress:</strong> ${task.progress}%</div>
                        <div class="mt-1 text-muted">${task.start} to ${task.end}</div>
                    </div>
                </div>
            `;
            },
            view_mode: 'Day', // Start with Day view for better visibility of short tasks
            language: 'en'
        });
        
        // Final visual adjustment: center the view on the tasks
        setTimeout(() => {
            const scrollContainer = document.querySelector('.gantt-container');
            if (scrollContainer) {
                scrollContainer.scrollLeft = (scrollContainer.scrollWidth - scrollContainer.clientWidth) / 2;
            }
        }, 500);

    } catch (e) {
        console.error(e);
        ganttChartContainer.innerHTML = `<div class="alert alert-danger">A critical error occurred while drawing the chart.</div>`;
    }
});
