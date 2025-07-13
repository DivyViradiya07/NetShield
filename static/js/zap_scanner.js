document.addEventListener('DOMContentLoaded', () => {
    // --- API Endpoints ---
    const API_BASE_URL = '/zap_scanner';
    const SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
    const RESULTS_ENDPOINT = `${API_BASE_URL}/scan_results`;
    const CLEAR_LOG_ENDPOINT = `${API_BASE_URL}/clear_log`;
    const LOG_STREAM_ENDPOINT = `${API_BASE_URL}/log_stream`;

    // --- DOM Elements ---
    const targetUrlInput = document.getElementById('targetUrl');
    const baselineScanBtn = document.getElementById('baselineScanBtn');
    const fullScanBtn = document.getElementById('fullScanBtn');
    const apiScanBtn = document.getElementById('apiScanBtn');
    const apiScanInputs = document.getElementById('apiScanInputs');
    const apiDefinitionPathInput = document.getElementById('apiDefinitionPath');
    const apiFormatSelect = document.getElementById('apiFormat');
    
    const scanStatus = document.getElementById('scanStatus');
    const logOutput = document.getElementById('logOutput');
    const clearLogBtn = document.getElementById('clearLogBtn');

    const lastScannedUrlDisplay = document.getElementById('lastScannedUrlDisplay');
    const totalAlertsDisplay = document.getElementById('totalAlertsDisplay');
    const highAlertsDisplay = document.getElementById('highAlertsDisplay');
    const mediumAlertsDisplay = document.getElementById('mediumAlertsDisplay');
    const lowAlertsDisplay = document.getElementById('lowAlertsDisplay');
    const infoAlertsDisplay = document.getElementById('infoAlertsDisplay');
    const zapAlertsTableBody = document.getElementById('zapAlertsTableBody');

    const resultsTabs = document.getElementById('resultsTabs');
    const resultsContent = document.getElementById('resultsContent');
    const refreshResultsBtn = document.getElementById('refreshResultsBtn');
    const copyResultsBtn = document.getElementById('copyResultsBtn');

    let currentActiveTab = 'baseline'; // Default active tab for results

    // --- Utility Functions ---

    /**
     * Shows a loading spinner and updates button text.
     * @param {HTMLElement} button The button element.
     */
    function showSpinner(button) {
        button.querySelector('.button-text').classList.add('hidden');
        button.querySelector('.spinner').classList.remove('hidden');
        button.disabled = true;
    }

    /**
     * Hides the loading spinner and restores button text.
     * @param {HTMLElement} button The button element.
     */
    function hideSpinner(button) {
        button.querySelector('.button-text').classList.remove('hidden');
        button.querySelector('.spinner').classList.add('hidden');
        button.disabled = false;
    }

    /**
     * Updates the scan status display.
     * @param {string} message The message to display.
     * @param {string} type 'success', 'error', or 'info' for styling.
     */
    function updateScanStatus(message, type = 'info') {
        scanStatus.textContent = message;
        scanStatus.classList.remove('bg-green-700', 'bg-red-700', 'bg-gray-700');
        scanStatus.classList.remove('text-green-400', 'text-red-400', 'text-gray-300');

        if (type === 'success') {
            scanStatus.classList.add('bg-green-700', 'text-green-400');
        } else if (type === 'error') {
            scanStatus.classList.add('bg-red-700', 'text-red-400');
        } else {
            scanStatus.classList.add('bg-gray-700', 'text-gray-300');
        }
    }

    /**
     * Appends a log message to the log output area and scrolls to the bottom.
     * @param {string} message The log message.
     */
    function appendLog(message) {
        const p = document.createElement('p');
        p.textContent = message;
        logOutput.appendChild(p);
        logOutput.scrollTop = logOutput.scrollHeight;
    }

    /**
     * Fetches and displays ZAP scan report summary in the table.
     * @param {string} scanType The type of scan report to fetch (baseline, full, api).
     */
    async function fetchAndDisplayZapReportSummary(scanType) {
        zapAlertsTableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">Loading alerts...</td></tr>`;
        try {
            const response = await fetch(`${RESULTS_ENDPOINT}?type=${scanType}`);
            const data = await response.json();

            if (data.status === 'success' && data.summary) {
                const summary = data.summary;
                lastScannedUrlDisplay.textContent = targetUrlInput.value || 'N/A'; // Update with current input URL
                totalAlertsDisplay.textContent = summary.Total;
                highAlertsDisplay.textContent = summary.High;
                mediumAlertsDisplay.textContent = summary.Medium;
                lowAlertsDisplay.textContent = summary.Low;
                infoAlertsDisplay.textContent = summary.Informational;

                zapAlertsTableBody.innerHTML = ''; // Clear existing rows

                if (summary.Details.length > 0) {
                    summary.Details.forEach(alert => {
                        const row = zapAlertsTableBody.insertRow();
                        row.classList.add('hover:bg-gray-700');
                        row.innerHTML = `
                            <td class="px-4 py-2 whitespace-nowrap text-sm font-medium ${getRiskColorClass(alert.risk)}">${alert.risk}</td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-200">${alert.name}</td>
                            <td class="px-4 py-2 text-sm text-gray-300 truncate max-w-xs"><a href="${alert.url}" target="_blank" class="text-blue-400 hover:underline">${alert.url}</a></td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${alert.confidence}</td>
                            <td class="px-4 py-2 text-sm text-gray-300 max-w-md overflow-hidden text-ellipsis">${alert.description.substring(0, 100)}...</td>
                        `;
                    });
                } else {
                    zapAlertsTableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">No alerts found for ${scanType} scan.</td></tr>`;
                }
            } else {
                zapAlertsTableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">${data.message || 'Error fetching alerts.'}</td></tr>`;
                lastScannedUrlDisplay.textContent = 'N/A';
                totalAlertsDisplay.textContent = '0';
                highAlertsDisplay.textContent = '0';
                mediumAlertsDisplay.textContent = '0';
                lowAlertsDisplay.textContent = '0';
                infoAlertsDisplay.textContent = '0';
            }
        } catch (error) {
            console.error('Error fetching ZAP report summary:', error);
            appendLog(`[!] Error fetching ZAP report summary: ${error.message}`);
            zapAlertsTableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-2 whitespace-nowrap text-sm text-red-400 text-center">Failed to load alerts.</td></tr>`;
        }
    }

    /**
     * Returns Tailwind CSS class for risk color.
     * @param {string} risk The risk level (High, Medium, Low, Informational).
     * @returns {string} Tailwind CSS class.
     */
    function getRiskColorClass(risk) {
        switch (risk) {
            case 'High': return 'text-red-500';
            case 'Medium': return 'text-orange-400';
            case 'Low': return 'text-yellow-400';
            case 'Informational': return 'text-blue-400';
            default: return 'text-gray-300';
        }
    }

    /**
     * Fetches and displays the raw JSON report content for a given scan type.
     * @param {string} scanType The type of scan report to fetch (baseline, full, api).
     */
    async function fetchAndDisplayScanResultsFile(scanType) {
        resultsContent.textContent = 'Loading raw report...';
        try {
            const response = await fetch(`${RESULTS_ENDPOINT}?type=${scanType}`);
            const data = await response.json();

            if (data.status === 'success' && data.summary) {
                // Display pretty-printed JSON
                resultsContent.textContent = JSON.stringify(data.summary, null, 2);
            } else {
                resultsContent.textContent = data.message || `No raw report available for ${scanType} scan.`;
            }
        } catch (error) {
            console.error('Error fetching raw ZAP report:', error);
            appendLog(`[!] Error fetching raw ZAP report: ${error.message}`);
            resultsContent.textContent = `Failed to load raw report for ${scanType}.`;
        }
    }

    /**
     * Handles the click event for ZAP scan buttons.
     * @param {Event} event The click event.
     * @param {string} scanType The type of scan to initiate.
     */
    async function handleScanButtonClick(event, scanType) {
        const button = event.currentTarget;
        showSpinner(button);
        updateScanStatus(`Initiating ${scanType} scan...`, 'info');
        logOutput.innerHTML = ''; // Clear log for new scan

        const targetUrl = targetUrlInput.value.trim();
        if (!targetUrl) {
            updateScanStatus("Error: Target URL cannot be empty.", 'error');
            appendLog("[!] Scan aborted: Target URL is empty.");
            hideSpinner(button);
            return;
        }

        const requestBody = {
            target_url: targetUrl,
            scan_type: scanType
        };

        if (scanType === 'api') {
            const apiDefinition = apiDefinitionPathInput.value.trim();
            const apiFormat = apiFormatSelect.value;
            if (!apiDefinition || !apiFormat) {
                updateScanStatus("Error: API Definition and Format are required for API scan.", 'error');
                appendLog("[!] Scan aborted: API Definition or Format missing.");
                hideSpinner(button);
                return;
            }
            requestBody.api_definition = apiDefinition;
            requestBody.api_format = apiFormat;
        }

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });
            const data = await response.json();

            if (data.status === 'success') {
                updateScanStatus(data.message, 'success');
                // After initiating scan, refresh results for the current active tab
                fetchAndDisplayZapReportSummary(currentActiveTab);
                fetchAndDisplayScanResultsFile(currentActiveTab);
            } else {
                updateScanStatus(`Error: ${data.message}`, 'error');
            }
        } catch (error) {
            console.error('Error initiating ZAP scan:', error);
            updateScanStatus(`Error: Could not connect to Flask backend or unexpected error: ${error.message}`, 'error');
            appendLog(`[!] Network error or unexpected response: ${error.message}`);
        } finally {
            hideSpinner(button);
        }
    }

    /**
     * Sets up the Server-Sent Events (SSE) stream for logs.
     */
    function setupLogStream() {
        const eventSource = new EventSource(LOG_STREAM_ENDPOINT);

        eventSource.onmessage = function(event) {
            // Log messages are sent as 'message' events
            appendLog(event.data);
        };

        eventSource.addEventListener('zap_scan_complete', function(event) {
            const data = JSON.parse(event.data);
            appendLog(`[+] SSE: ZAP ${data.scan_type.toUpperCase()} scan complete for ${data.target_url}.`);
            // Automatically refresh results when a scan completes
            fetchAndDisplayZapReportSummary(data.scan_type);
            fetchAndDisplayScanResultsFile(data.scan_type);
        });

        eventSource.addEventListener('zap_report_parsed', function(event) {
            const data = JSON.parse(event.data);
            appendLog(`[+] SSE: ZAP report parsed. Total Alerts: ${data.Total}`);
            // The summary display is handled by fetchAndDisplayZapReportSummary
        });

        eventSource.onerror = function(error) {
            console.error('EventSource failed:', error);
            eventSource.close(); // Close the connection on error
            appendLog("[!] Log stream disconnected. Attempting to re-establish in 5 seconds...");
            setTimeout(setupLogStream, 5000); // Attempt to reconnect after 5 seconds
        };
    }

    /**
     * Copies the content of the resultsContent area to the clipboard.
     */
    function copyResultsToClipboard() {
        const textToCopy = resultsContent.textContent;
        if (textToCopy === 'Select a scan type to view raw JSON report.' || textToCopy.trim() === '') {
            alert('No results to copy.');
            return;
        }
        // Use execCommand for broader compatibility within iframes
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            alert('Results copied to clipboard!');
        } catch (err) {
            console.error('Failed to copy text: ', err);
            alert('Failed to copy results. Please copy manually.');
        } finally {
            document.body.removeChild(textarea);
        }
    }

    /**
     * Initializes the UI on page load.
     */
    function initializeUI() {
        // Set initial tab and display its results
        document.getElementById(`${currentActiveTab}-tab`).classList.add('active');
        fetchAndDisplayZapReportSummary(currentActiveTab);
        fetchAndDisplayScanResultsFile(currentActiveTab);
        setupLogStream(); // Start log streaming
    }

    // --- Event Listeners ---
    baselineScanBtn.addEventListener('click', (event) => handleScanButtonClick(event, 'baseline'));
    fullScanBtn.addEventListener('click', (event) => handleScanButtonClick(event, 'full'));
    apiScanBtn.addEventListener('click', (event) => {
        handleScanButtonClick(event, 'api');
    });

    // Toggle visibility of API scan inputs
    apiScanBtn.addEventListener('click', () => {
        apiScanInputs.classList.toggle('hidden');
    });

    clearLogBtn.addEventListener('click', async () => {
        showSpinner(clearLogBtn);
        try {
            const response = await fetch(CLEAR_LOG_ENDPOINT, { method: 'POST' });
            const data = await response.json();
            if (data.status === 'success') {
                logOutput.innerHTML = '';
                appendLog("[*] Log file cleared by user.");
                updateScanStatus("Log cleared.", 'info');
            } else {
                updateScanStatus(`Error clearing log: ${data.message}`, 'error');
            }
        } catch (error) {
            console.error('Error clearing log:', error);
            updateScanStatus(`Error clearing log: ${error.message}`, 'error');
        } finally {
            hideSpinner(clearLogBtn);
        }
    });

    refreshResultsBtn.addEventListener('click', () => {
        fetchAndDisplayZapReportSummary(currentActiveTab);
        fetchAndDisplayScanResultsFile(currentActiveTab);
        appendLog(`[*] Refreshed results for ${currentActiveTab} tab.`);
    });

    copyResultsBtn.addEventListener('click', copyResultsToClipboard);

    // Tab switching for scan results
    resultsTabs.querySelectorAll('button').forEach(button => {
        button.addEventListener('click', () => {
            // Deactivate current active tab
            resultsTabs.querySelector('.active').classList.remove('active');
            // Activate clicked tab
            button.classList.add('active');
            currentActiveTab = button.dataset.tab;
            // Fetch and display results for the new active tab
            fetchAndDisplayZapReportSummary(currentActiveTab);
            fetchAndDisplayScanResultsFile(currentActiveTab);
        });
    });

    // Initialize UI on page load
    initializeUI();
});
