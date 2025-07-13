document.addEventListener('DOMContentLoaded', function() {
    const targetHostInput = document.getElementById('targetHost');
    const initiateScanBtn = document.getElementById('initiateScanBtn');
    const scanStatus = document.getElementById('scanStatus');
    const clearLogBtn = document.getElementById('clearLogBtn');
    const logOutput = document.getElementById('logOutput');
    const resultsContent = document.getElementById('resultsContent');
    const copyResultsBtn = document.getElementById('copyResultsBtn');
    const refreshReportBtn = document.getElementById('refreshReportBtn');
    const customMessageBox = document.getElementById('customMessageBox');

    // Summary elements
    const summaryTarget = document.getElementById('summaryTarget');
    const summaryIp = document.getElementById('summaryIp');
    const summaryPort = document.getElementById('summaryPort');

    // Certificate details
    const certCommonName = document.getElementById('certCommonName');
    const certIssuer = document.getElementById('certIssuer');
    const certNotBefore = document.getElementById('certNotBefore');
    const certNotAfter = document.getElementById('certNotAfter');
    const certSignatureAlgo = document.getElementById('certSignatureAlgo');
    const certKeySize = document.getElementById('certKeySize');
    const certAltNames = document.getElementById('certAltNames');

    // Tables/Lists
    const protocolsTableBody = document.getElementById('protocolsTableBody');
    const ciphersTableBody = document.getElementById('ciphersTableBody');
    const clientCAsList = document.getElementById('clientCAsList');
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');

    let eventSource = null; // For Server-Sent Events

    // Function to display messages in the custom message box
    function displayMessageBox(message, type = 'info') {
        customMessageBox.textContent = message;
        customMessageBox.className = 'fixed bottom-4 right-4 p-3 rounded-lg shadow-lg z-50 transition-transform transform opacity-0'; // Reset classes
        
        if (type === 'success') {
            customMessageBox.classList.add('bg-green-600', 'text-white');
        } else if (type === 'error') {
            customMessageBox.classList.add('bg-red-600', 'text-white');
        } else {
            customMessageBox.classList.add('bg-gray-700', 'text-white');
        }

        customMessageBox.classList.remove('translate-y-full', 'opacity-0');
        customMessageBox.classList.add('translate-y-0', 'opacity-100');

        setTimeout(() => {
            customMessageBox.classList.remove('translate-y-0', 'opacity-100');
            customMessageBox.classList.add('translate-y-full', 'opacity-0');
        }, 3000);
    }

    // Function to update button state (loading spinner)
    function updateButtonState(button, isLoading) {
        const buttonText = button.querySelector('.button-text');
        const spinner = button.querySelector('.spinner');
        if (isLoading) {
            button.disabled = true;
            buttonText.classList.add('hidden');
            spinner.classList.remove('hidden');
        } else {
            button.disabled = false;
            buttonText.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    }

    // Function to clear all displayed scan results
    function clearScanResults() {
        summaryTarget.textContent = 'N/A';
        summaryIp.textContent = 'N/A';
        summaryPort.textContent = 'N/A';

        certCommonName.textContent = 'N/A';
        certIssuer.textContent = 'N/A';
        certNotBefore.textContent = 'N/A';
        certNotAfter.textContent = 'N/A';
        certSignatureAlgo.textContent = 'N/A';
        certKeySize.textContent = 'N/A';
        certAltNames.textContent = 'N/A';

        protocolsTableBody.innerHTML = '<tr class="empty-table-message"><td colspan="4" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">No protocols detected.</td></tr>';
        ciphersTableBody.innerHTML = '<tr class="empty-table-message"><td colspan="5" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">No ciphers detected.</td></tr>';
        clientCAsList.innerHTML = '<li>No Client CAs detected.</li>';
        vulnerabilitiesList.innerHTML = '<li>No vulnerabilities detected.</li>';
        resultsContent.textContent = 'Raw XML report will appear here after a scan.';
    }

    // Function to fetch and display the SSL report
    async function fetchAndDisplayReport() {
        try {
            const response = await fetch('/ssl_scanner/report');
            const data = await response.json();

            if (data.status === 'success') {
                resultsContent.textContent = data.content;
                displayMessageBox('Raw report loaded successfully.', 'success');
                
                // Parse and display structured data
                const parser = new DOMParser();
                const xmlDoc = parser.parseFromString(data.content, "text/xml");

                // Summary
                const ssltestElem = xmlDoc.querySelector('ssltest');
                if (ssltestElem) {
                    summaryTarget.textContent = ssltestElem.getAttribute('host') || 'N/A';
                    // IP is not an attribute in the provided XML for ssltest
                    summaryIp.textContent = ssltestElem.getAttribute('ip') || 'N/A'; 
                    summaryPort.textContent = ssltestElem.getAttribute('port') || 'N/A';
                }

                // Protocols
                protocolsTableBody.innerHTML = ''; // Clear previous entries
                const protocols = xmlDoc.querySelectorAll('protocol');
                if (protocols.length > 0) {
                    protocols.forEach(p => {
                        const row = protocolsTableBody.insertRow();
                        row.className = 'hover:bg-gray-700';
                        row.innerHTML = `
                            <td class="px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-100">${p.getAttribute('version') || 'N/A'}</td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${p.getAttribute('type') || 'N/A'}</td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${p.getAttribute('enabled') === '1' ? 'Enabled' : 'Disabled'}</td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${p.getAttribute('notes') || 'N/A'}</td>
                        `;
                    });
                } else {
                    protocolsTableBody.innerHTML = '<tr class="empty-table-message"><td colspan="4" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">No protocols detected.</td></tr>';
                }

                // Ciphers
                ciphersTableBody.innerHTML = ''; // Clear previous entries
                const ciphers = xmlDoc.querySelectorAll('cipher');
                if (ciphers.length > 0) {
                    ciphers.forEach(c => {
                        const row = ciphersTableBody.insertRow();
                        row.className = 'hover:bg-gray-700';
                        row.innerHTML = `
                            <td class="px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-100">${c.getAttribute('sslversion') || 'N/A'}</td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${c.getAttribute('bits') || 'N/A'}</td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${c.getAttribute('strength') || 'N/A'}</td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${c.getAttribute('cipher') || 'N/A'}</td>
                            <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${c.getAttribute('id') || 'N/A'}</td>
                        `;
                    });
                } else {
                    ciphersTableBody.innerHTML = '<tr class="empty-table-message"><td colspan="5" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">No ciphers detected.</td></tr>';
                }

                // Certificate Details
                const certElem = xmlDoc.querySelector('certificate');
                if (certElem) {
                    const pkElem = certElem.querySelector('pk');
                    certCommonName.textContent = certElem.querySelector('subject')?.textContent || 'N/A';
                    certIssuer.textContent = certElem.querySelector('issuer')?.textContent || 'N/A';
                    certNotBefore.textContent = certElem.querySelector('not-valid-before')?.textContent || 'N/A';
                    certNotAfter.textContent = certElem.querySelector('not-valid-after')?.textContent || 'N/A';
                    certSignatureAlgo.textContent = certElem.querySelector('signature-algorithm')?.textContent || 'N/A';
                    certKeySize.textContent = pkElem ? (pkElem.getAttribute('bits') || 'N/A') : 'N/A';
                    
                    const altNames = Array.from(certElem.querySelectorAll('altnames altname')).map(an => an.textContent);
                    certAltNames.textContent = altNames.length > 0 ? altNames.join(', ') : 'N/A';
                } else {
                    certCommonName.textContent = 'N/A';
                    certIssuer.textContent = 'N/A';
                    certNotBefore.textContent = 'N/A';
                    certNotAfter.textContent = 'N/A';
                    certSignatureAlgo.textContent = 'N/A';
                    certKeySize.textContent = 'N/A';
                    certAltNames.textContent = 'N/A';
                }

                // Client CAs
                clientCAsList.innerHTML = '';
                const clientCAs = xmlDoc.querySelectorAll('client-cas ca');
                if (clientCAs.length > 0) {
                    clientCAs.forEach(ca => {
                        const li = document.createElement('li');
                        li.textContent = ca.getAttribute('name') || 'N/A';
                        clientCAsList.appendChild(li);
                    });
                } else {
                    clientCAsList.innerHTML = '<li>No Client CAs detected.</li>';
                }

                // Vulnerabilities
                vulnerabilitiesList.innerHTML = '';
                const vulnerabilities = [];
                
                // Heartbleed
                xmlDoc.querySelectorAll('heartbleed[vulnerable="1"]').forEach(hb => {
                    vulnerabilities.push(`Heartbleed (TLSv${hb.getAttribute('sslversion')}): Vulnerable`);
                });

                // Other vulnerabilities from notes (can be expanded based on actual output)
                xmlDoc.querySelectorAll('protocol[notes*="vulnerable"], protocol[notes*="weak"], cipher[notes*="vulnerable"], cipher[notes*="weak"]').forEach(elem => {
                    const type = elem.tagName;
                    const name = elem.getAttribute('version') || elem.getAttribute('cipher');
                    const notes = elem.getAttribute('notes');
                    vulnerabilities.push(`${name} (${type}): ${notes}`);
                });

                if (vulnerabilities.length > 0) {
                    vulnerabilities.forEach(vuln => {
                        const li = document.createElement('li');
                        li.textContent = vuln;
                        vulnerabilitiesList.appendChild(li);
                    });
                } else {
                    vulnerabilitiesList.innerHTML = '<li>No vulnerabilities detected.</li>';
                }


            } else {
                resultsContent.textContent = data.message;
                displayMessageBox(`Error loading report: ${data.message}`, 'error');
            }
        } catch (error) {
            console.error('Error fetching/parsing SSL report:', error);
            resultsContent.textContent = `Error: ${error.message}`;
            displayMessageBox('Failed to load SSL report.', 'error');
        }
    }

    // Initiate Scan Button Click
    initiateScanBtn.addEventListener('click', async () => {
        const targetHost = targetHostInput.value.trim();
        if (!targetHost) {
            displayMessageBox('Please enter a target host.', 'error');
            return;
        }

        clearScanResults(); // Clear previous results
        logOutput.textContent = ''; // Clear log on new scan
        updateButtonState(initiateScanBtn, true);
        scanStatus.textContent = 'Scanning...';
        scanStatus.classList.remove('text-green-400', 'text-red-400');
        scanStatus.classList.add('text-yellow-400');

        try {
            const response = await fetch('/ssl_scanner/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target_host: targetHost })
            });
            const data = await response.json();

            if (data.status === 'success') {
                displayMessageBox(data.message, 'success');
                scanStatus.textContent = 'Scan Initiated';
                scanStatus.classList.remove('text-yellow-400');
                scanStatus.classList.add('text-green-400');
                // Report will be fetched by the SSE 'ssl_scan_complete' event
            } else {
                displayMessageBox(`Scan initiation failed: ${data.message}`, 'error');
                scanStatus.textContent = 'Scan Failed';
                scanStatus.classList.remove('text-yellow-400');
                scanStatus.classList.add('text-red-400');
                updateButtonState(initiateScanBtn, false); // Re-enable button on immediate failure
            }
        } catch (error) {
            console.error('Error initiating SSL scan:', error);
            displayMessageBox('Failed to initiate SSL scan due to network error.', 'error');
            scanStatus.textContent = 'Scan Failed';
            scanStatus.classList.remove('text-yellow-400');
            scanStatus.classList.add('text-red-400');
            updateButtonState(initiateScanBtn, false);
        }
    });

    // Clear Log Button Click
    clearLogBtn.addEventListener('click', async () => {
        updateButtonState(clearLogBtn, true);
        try {
            const response = await fetch('/ssl_scanner/clear_log', {
                method: 'POST'
            });
            const data = await response.json();
            if (data.status === 'success') {
                logOutput.textContent = ''; // Clear frontend log display
                displayMessageBox(data.message, 'success');
            } else {
                displayMessageBox(`Failed to clear log: ${data.message}`, 'error');
            }
        } catch (error) {
            console.error('Error clearing log:', error);
            displayMessageBox('Failed to clear log due to network error.', 'error');
        } finally {
            updateButtonState(clearLogBtn, false);
        }
    });

    // Copy Results Button Click
    copyResultsBtn.addEventListener('click', () => {
        const textToCopy = resultsContent.textContent;
        if (textToCopy === 'Raw XML report will appear here after a scan.' || textToCopy.trim() === '') {
            displayMessageBox('No report content to copy.', 'info');
            return;
        }
        // Use a fallback for document.execCommand('copy') as navigator.clipboard.writeText() might not work in iframes
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        textarea.style.position = 'fixed'; // Avoid scrolling to bottom
        textarea.style.opacity = 0;
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        try {
            document.execCommand('copy');
            displayMessageBox('Report copied to clipboard!', 'success');
        } catch (err) {
            console.error('Failed to copy text: ', err);
            displayMessageBox('Failed to copy report.', 'error');
        } finally {
            document.body.removeChild(textarea);
        }
    });

    // Refresh Report Button Click
    refreshReportBtn.addEventListener('click', fetchAndDisplayReport);

    // Setup Server-Sent Events for real-time logging
    function setupLogStream() {
        if (eventSource) {
            eventSource.close();
        }
        eventSource = new EventSource('/ssl_scanner/log_stream');

        eventSource.onmessage = function(event) {
            const message = event.data;
            logOutput.textContent += message + '\n';
            logOutput.scrollTop = logOutput.scrollHeight; // Auto-scroll to bottom
        };

        eventSource.addEventListener('ssl_scan_complete', function(event) {
            const data = JSON.parse(event.data);
            displayMessageBox(`SSL Scan complete for ${data.target_host}.`, 'success');
            scanStatus.textContent = 'Scan Complete';
            scanStatus.classList.remove('text-yellow-400', 'text-red-400');
            scanStatus.classList.add('text-green-400');
            updateButtonState(initiateScanBtn, false); // Re-enable scan button
            fetchAndDisplayReport(); // Fetch and display the full report
        });

        eventSource.addEventListener('ssl_report_parsed', function(event) {
            // This event is already handled by fetchAndDisplayReport,
            // but we can use it to confirm parsing on the frontend if needed.
            console.log("SSL Report parsed event received:", JSON.parse(event.data));
        });

        eventSource.onerror = function(err) {
            console.error('EventSource failed:', err);
            // Attempt to reconnect after a delay
            eventSource.close();
            setTimeout(setupLogStream, 3000); // Reconnect after 3 seconds
        };
    }

    // Initial setup
    setupLogStream();
    clearScanResults(); // Clear results on page load
    fetchAndDisplayReport(); // Attempt to load any existing report on page load
});
