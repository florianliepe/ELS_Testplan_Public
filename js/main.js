document.addEventListener('DOMContentLoaded', () => {
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const uploadStatus = document.getElementById('upload-status');

    // --- Event Listeners ---

    // Prevent default browser behavior for drag-and-drop
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });

    // Add a visual indicator when a file is dragged over
    ['dragenter', 'dragover'].forEach(eventName => {
        uploadArea.addEventListener(eventName, () => {
            uploadArea.classList.add('dragover');
        }, false);
    });

    // Remove the visual indicator when the file leaves
    ['dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, () => {
            uploadArea.classList.remove('dragover');
        }, false);
    });

    // Handle the file drop
    uploadArea.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    }, false);

    // Allow clicking the area to open the file browser
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });

    // Handle file selection from the file browser
    fileInput.addEventListener('change', (e) => {
        const files = e.target.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    // --- Core File Handling Function ---

    function handleFile(file) {
        // Check if the file is an Excel file
        const validExtensions = ['.xlsx', '.xls', '.csv'];
        const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

        if (!validExtensions.includes(fileExtension)) {
            showStatus('Error: Please upload a valid Excel file (.xlsx, .xls, or .csv).', true);
            return;
        }

        showStatus(`Processing "${file.name}"...`, false);

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const data = e.target.result;
                const workbook = XLSX.read(data, { type: 'binary' });

                const requiredSheets = ['Test Plan', 'Preparation Tasks', 'Blockers'];
                let allSheetsFound = true;

                // Clear any old data from previous sessions
                sessionStorage.clear();

                requiredSheets.forEach(sheetName => {
                    if (workbook.Sheets[sheetName]) {
                        const jsonData = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName]);
                        sessionStorage.setItem(sheetName, JSON.stringify(jsonData));
                        console.log(`Successfully processed and stored "${sheetName}".`);
                    } else {
                        showStatus(`Error: Required sheet "${sheetName}" was not found in the Excel file.`, true);
                        allSheetsFound = false;
                    }
                });

                if (allSheetsFound) {
                    showStatus('Success! Redirecting to dashboard...', false);
                    // Redirect to the dashboard after a short delay
                    setTimeout(() => {
                        window.location.href = 'dashboard.html';
                    }, 1000);
                }

            } catch (error) {
                console.error(error);
                showStatus('An unexpected error occurred while processing the file.', true);
            }
        };

        reader.onerror = (error) => {
            console.error(error);
            showStatus('Error reading the file.', true);
        };

        reader.readAsBinaryString(file);
    }

    function showStatus(message, isError) {
        uploadStatus.textContent = message;
        uploadStatus.className = 'status-message'; // Reset classes
        if (isError) {
            uploadStatus.classList.add('status-error');
        } else {
            uploadStatus.classList.add('status-success');
        }
    }
});
