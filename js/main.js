document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('excel-file-input');
    const messageArea = document.getElementById('message-area');

    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect);
    }

    function handleFileSelect(event) {
        const file = event.target.files[0];
        if (!file) {
            messageArea.textContent = 'No file selected.';
            return;
        }

        messageArea.textContent = 'Processing file...';

        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const data = new Uint8Array(e.target.result);
                const workbook = XLSX.read(data, { type: 'array' });

                // Define the sheets we want to extract
                const requiredSheets = ['Test Plan', 'Preparation Tasks', 'Blockers'];
                let allSheetsFound = true;

                requiredSheets.forEach(sheetName => {
                    if (workbook.SheetNames.includes(sheetName)) {
                        const worksheet = workbook.Sheets[sheetName];
                        // Convert sheet to JSON format
                        const jsonData = XLSX.utils.sheet_to_json(worksheet);
                        // Store the JSON data in the browser's session storage
                        sessionStorage.setItem(sheetName, JSON.stringify(jsonData));
                        console.log(`Successfully processed and stored '${sheetName}'`);
                    } else {
                        allSheetsFound = false;
                        console.error(`Sheet '${sheetName}' not found in the Excel file.`);
                    }
                });

                if (allSheetsFound) {
                    messageArea.textContent = 'File processed successfully! Redirecting to dashboard...';
                    // Redirect to the dashboard page after a short delay
                    setTimeout(() => {
                        window.location.href = 'dashboard.html';
                    }, 1500);
                } else {
                    messageArea.textContent = 'Error: One or more required sheets were not found in the file. Please check the Excel file.';
                }

            } catch (error) {
                messageArea.textContent = `An error occurred while processing the file: ${error.message}`;
                console.error(error);
            }
        };

        reader.onerror = function() {
            messageArea.textContent = 'Failed to read the file.';
        };

        reader.readAsArrayBuffer(file);
    }
});
