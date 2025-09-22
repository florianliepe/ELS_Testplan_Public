function exportDataToExcel() {
    try {
        // 1. Create a new workbook
        const workbook = XLSX.utils.book_new();

        // 2. Define the sheets to be exported
        const sheetNames = ['Test Plan', 'Preparation Tasks', 'Blockers'];

        let dataFound = false;

        // 3. Process each sheet
        sheetNames.forEach(sheetName => {
            const jsonDataString = sessionStorage.getItem(sheetName);
            if (jsonDataString) {
                dataFound = true;
                const jsonData = JSON.parse(jsonDataString);
                
                // Convert the JSON data to a worksheet
                const worksheet = XLSX.utils.json_to_sheet(jsonData);
                
                // Add the worksheet to the workbook with the correct name
                XLSX.utils.book_append_sheet(workbook, worksheet, sheetName);
                console.log(`Added "${sheetName}" to the export workbook.`);
            } else {
                console.warn(`No data found in sessionStorage for "${sheetName}". Skipping.`);
            }
        });

        if (!dataFound) {
            alert("No data available to export. Please upload an Excel file first.");
            return;
        }

        // 4. Generate a filename with the current date
        const today = new Date().toISOString().slice(0, 10); // Format: YYYY-MM-DD
        const fileName = `Test_Plan_Export_${today}.xlsx`;

        // 5. Trigger the download
        XLSX.writeFile(workbook, fileName);

    } catch (error) {
        console.error("An error occurred during the Excel export:", error);
        alert("An error occurred while trying to export the data. Please check the console for details.");
    }
}
