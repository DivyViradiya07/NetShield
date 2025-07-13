// --- Configuration ---
// Base URL for your Flask backend (adjust if your Flask app runs on a different port/IP)
const BASE_URL = "http://127.0.0.1:5000/chatbot"; // Assuming Flask blueprint is registered at /chatbot
// Base URL for your FastAPI backend (adjust if your FastAPI app runs on a different port/IP)
const FASTAPI_BACKEND_URL = "http://192.168.0.156:8000";

const MAX_FILE_SIZE_MB = 100;
const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

// --- DOM Elements ---
const uploadForm = document.getElementById('upload-form');
const uploadButton = document.getElementById('upload-button');
const uploadError = document.getElementById('upload-error');
const llmModeSelector = document.getElementById('llm_mode_selector');

const welcomePanel = document.getElementById('welcome-panel');
const chatPanel = document.getElementById('chat-panel');
const chatHistory = document.getElementById('chat-history');
const userInput = document.getElementById('user-input');
const sendButton = document.getElementById('send-button');
const chatError = document.getElementById('chat-error');
const loadingIndicator = document.getElementById('loading-indicator');
const fileInput = document.getElementById('report_file');
const copyFlash = document.getElementById('copy-flash');
// const chatPlaceholder = document.getElementById('chat-placeholder'); // This element will be removed directly by clearing chatHistory.innerHTML

// --- State Variables ---
let chatContext = [];
// These variables would typically be passed from Flask via Jinja2.
// For a standalone HTML/JS, we initialize them to default states.
let initialAnalysisFromFlask = null; // Set to null for standalone HTML
let isProcessingFromFlask = false; // Set to false for standalone HTML

let currentSessionId = null; // To store the session ID received from the backend
let currentLlmMode = 'local'; // Default LLM mode, will be updated from selector

// --- Functions ---

/**
 * Initializes the UI state based on whether there's an initial analysis or processing flag.
 * For standalone HTML, this will default to showing the welcome panel.
 */
function initializeUI() {
    console.log("UI Initializing...");
    console.log("initialAnalysisFromFlask:", initialAnalysisFromFlask);
    console.log("isProcessingFromFlask:", isProcessingFromFlask);

    if (initialAnalysisFromFlask) {
        console.log("Initial analysis present. Displaying chat panel with summary.");
        welcomePanel.classList.add('hidden');
        chatPanel.classList.remove('hidden');
        appendMessage('AI', initialAnalysisFromFlask);
        chatContext.push({ role: 'assistant', content: initialAnalysisFromFlask });
        userInput.disabled = false;
        sendButton.disabled = false;
    } else if (isProcessingFromFlask) {
        console.log("Processing flag true. Displaying chat panel with loading message.");
        welcomePanel.classList.add('hidden');
        chatPanel.classList.remove('hidden');
        userInput.disabled = true;
        sendButton.disabled = true;
        // The automatic fetch for processing would be triggered here if `filename` was available
        // For standalone, this part won't execute as `isProcessingFromFlask` is false.
    } else {
        console.log("No initial analysis or processing. Displaying welcome panel.");
        welcomePanel.classList.remove('hidden');
        chatPanel.classList.add('hidden');
        userInput.disabled = true;
        sendButton.disabled = true;
    }
    // Ensure the current LLM mode is picked up from the selector on page load
    currentLlmMode = llmModeSelector.value;
    console.log("Current LLM Mode on load:", currentLlmMode);
}

/**
 * Appends a message to the chat history.
 * @param {string} sender - 'You' or 'AI'.
 * @param {string} message - The message content.
 */
function appendMessage(sender, message) {
    console.log(`Appending message from ${sender}:`, message);
    const messageWrapper = document.createElement('div');
    messageWrapper.classList.add('flex', 'mb-4', 'items-start');

    const messageBubble = document.createElement('div');
    messageBubble.classList.add('p-3', 'rounded-xl', 'max-w-[75%]', 'relative', 'group');

    const copyButton = document.createElement('button');
    copyButton.innerHTML = '<span class="material-symbols-outlined text-gray-700 text-sm">content_copy</span>';
    copyButton.title = 'Copy to clipboard';
    copyButton.classList.add('absolute', 'top-2', 'right-2', 'bg-gray-100', 'hover:bg-gray-200', 'text-gray-700', 'p-1.5', 'rounded-full', 'opacity-0', 'group-hover:opacity-100', 'transition-opacity', 'duration-200', 'focus:outline-none', 'z-10', 'flex', 'items-center', 'justify-center', 'shadow-sm');

    if (sender === 'You') {
        messageWrapper.classList.add('justify-end');
        messageBubble.classList.add('bg-blue-600', 'text-white', 'rounded-br-none');
        messageBubble.innerHTML = escapeHtml(message);
    } else {
        // AI messages
        messageWrapper.classList.add('justify-start');
        messageBubble.classList.add('bg-gray-100', 'text-gray-800', 'rounded-bl-none');
        // Use marked.parse for AI messages to render Markdown
        messageBubble.innerHTML = marked.parse(message);

        copyButton.addEventListener('click', function () {
            const tempElement = document.createElement('div');
            tempElement.innerHTML = marked.parse(message);
            // Use document.execCommand('copy') for clipboard operations in iframe environments
            const textToCopy = tempElement.innerText;
            const textarea = document.createElement('textarea');
            textarea.value = textToCopy;
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                copyFlash.classList.remove('opacity-0');
                setTimeout(() => {
                    copyFlash.classList.add('opacity-0');
                }, 1500);
            } catch (err) {
                console.error('Failed to copy text: ', err);
                // Optionally, show a message to the user that copy failed
            } finally {
                document.body.removeChild(textarea);
            }
        });
        messageBubble.appendChild(copyButton);
    }

    // Avatar handling
    if (sender === 'AI') {
        const aiAvatar = document.createElement('div');
        aiAvatar.classList.add('message-avatar', 'ai', 'mr-3');
        aiAvatar.innerHTML = '<span class="material-symbols-outlined text-white text-base">psychology</span>';
        messageWrapper.insertBefore(aiAvatar, messageWrapper.firstChild);
    } else {
        const userAvatar = document.createElement('div');
        userAvatar.classList.add('message-avatar', 'user', 'ml-3');
        userAvatar.innerHTML = '<span class="material-symbols-outlined text-white text-base">person</span>';
        messageWrapper.appendChild(userAvatar);
    }

    messageWrapper.appendChild(messageBubble);
    chatHistory.appendChild(messageWrapper);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

/**
 * Escapes HTML characters in a string to prevent XSS.
 * @param {string} unsafe - The string to escape.
 * @returns {string} The escaped string.
 */
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// --- Event Listeners ---

// Call initializeUI on page load
document.addEventListener('DOMContentLoaded', initializeUI);

// Event listener for the Upload button
if (uploadButton) {
    uploadButton.addEventListener('click', function () {
        const file = fileInput.files[0];
        currentLlmMode = llmModeSelector.value; // Always get the latest selected LLM mode

        console.log("Upload button clicked. Selected LLM Mode:", currentLlmMode);

        if (!file) {
            uploadError.textContent = 'Please select a PDF report to upload.';
            uploadError.classList.remove('hidden');
            console.warn("No file selected.");
            return;
        }

        if (file.type !== 'application/pdf') {
            uploadError.textContent = 'Only PDF files are supported.';
            uploadError.classList.remove('hidden');
            console.warn("Invalid file type:", file.type);
            return;
        }

        if (file.size > MAX_FILE_SIZE_BYTES) {
            uploadError.textContent = `File size exceeds the limit of ${MAX_FILE_SIZE_MB}MB.`;
            uploadError.classList.remove('hidden');
            console.warn("File size too large:", file.size);
            return;
        }

        // --- UI Updates before Fetch ---
        uploadError.classList.add('hidden'); // Hide any previous upload error
        welcomePanel.classList.add('hidden'); // Hide welcome panel
        loadingIndicator.classList.remove('hidden'); // Show general loading indicator
        chatHistory.innerHTML = ''; // Clear chat history to prepare for new content
        chatContext = []; // Reset chat context
        userInput.disabled = true;
        sendButton.disabled = true;
        chatPanel.classList.remove('hidden'); // Ensure chat panel is visible

        // Add a dynamic loading message to chat history immediately
        const processingLoadingMessage = document.createElement('div');
        processingLoadingMessage.className = 'message ai-message mb-4 flex items-start';
        processingLoadingMessage.innerHTML = `
            <div class="message-avatar ai mr-3"><span class="material-symbols-outlined text-white text-base">psychology</span></div>
            <div class="bg-blue-50 p-3 rounded-xl max-w-[75%]">
                <div class="flex items-center text-blue-700">
                    <div class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500 mr-2"></div>
                    <p>Uploading and processing your report. Please wait...</p>
                </div>
            </div>
        `;
        chatHistory.appendChild(processingLoadingMessage);
        chatHistory.scrollTop = chatHistory.scrollHeight; // Scroll to bottom

        const formData = new FormData();
        formData.append('report_file', file); // Matches Flask's expected field name
        formData.append('llm_mode', currentLlmMode); // Send the chosen LLM mode to Flask

        console.log("Sending upload request to Flask backend:", `${BASE_URL}/upload_report`);
        fetch(`${BASE_URL}/upload_report`, {
            method: 'POST',
            body: formData,
        })
            .then(response => {
                console.log("Received response from Flask upload. Status:", response.status);
                if (!response.ok) {
                    return response.json().then(err => { throw new Error(err.error || 'Unknown upload error'); });
                }
                return response.json();
            })
            .then(data => {
                console.log("Upload response data from Flask:", data);
                processingLoadingMessage.remove(); // Remove dynamic loading message
                loadingIndicator.classList.add('hidden'); // Hide general loading indicator

                if (data.error) {
                    uploadError.textContent = data.error;
                    uploadError.classList.remove('hidden');
                    appendMessage('AI', `Error processing report: ${data.error}`); // Display error in chat as well
                    console.error("Flask returned an error:", data.error);
                } else if (data.message) { // Frontend expects 'message' from Flask
                    currentSessionId = data.session_id; // Store the session ID returned by Flask
                    userInput.disabled = false;
                    sendButton.disabled = false;

                    console.log("Summary received from Flask. Appending to chat history.");
                    appendMessage('AI', data.message); // THIS IS WHERE THE SUMMARY GETS ADDED
                    chatContext.push({ role: 'assistant', content: data.message });
                    console.log("Report uploaded and summary displayed. Session ID:", currentSessionId);
                } else {
                    // Fallback if 'message' or 'error' is not in data
                    uploadError.textContent = 'Unexpected response from server. Check console.';
                    uploadError.classList.remove('hidden');
                    appendMessage('AI', 'An unexpected response was received after report upload.');
                    console.error("Unexpected data structure from Flask upload:", data);
                }
            })
            .catch(error => {
                console.error('Upload fetch error (catch block):', error);
                processingLoadingMessage.remove(); // Remove dynamic loading message
                loadingIndicator.classList.add('hidden');
                uploadError.textContent = `An error occurred during file upload: ${error.message}. Check console for details.`;
                uploadError.classList.remove('hidden');
                appendMessage('AI', `Error: An unexpected network or processing error occurred during upload: ${error.message}`);
            });
    });
}

// Event listener for the Send button (chat input)
sendButton.addEventListener('click', function () {
    const userMessage = userInput.value.trim();
    if (userMessage) {
        appendMessage('You', userMessage);
        userInput.value = '';
        loadingIndicator.classList.remove('hidden');
        chatError.classList.add('hidden');
        userInput.disabled = true;
        sendButton.disabled = true;

        console.log("Sending chat message to Flask backend for session:", currentSessionId);
        fetch(`${BASE_URL}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                message: userMessage,
                session_id: currentSessionId // Send session ID
                // llm_mode is now stored in Flask session after upload, no need to send it again here.
            }),
        })
            .then(response => {
                console.log("Received response from Flask chat. Status:", response.status);
                if (!response.ok) {
                    return response.json().then(err => { throw new Error(err.error || 'Unknown chat error'); });
                }
                return response.json();
            })
            .then(data => {
                console.log("Chat response data from Flask:", data);
                loadingIndicator.classList.add('hidden');
                userInput.disabled = false;
                sendButton.disabled = false;
                if (data.error) {
                    chatError.textContent = data.error;
                    chatError.classList.remove('hidden');
                    appendMessage('AI', `Error: ${data.error}`);
                    console.error("Flask returned chat error:", data.error);
                } else if (data.response) {
                    appendMessage('AI', data.response);
                    chatContext.push({ role: 'assistant', content: data.response });
                    console.log("AI response displayed.");
                } else {
                    // Fallback if 'response' or 'error' is not in data
                    chatError.textContent = 'Unexpected response from server during chat. Check console.';
                    chatError.classList.remove('hidden');
                    appendMessage('AI', 'An unexpected response was received during chat.');
                    console.error("Unexpected data structure from Flask chat:", data);
                }
            })
            .catch(error => {
                console.error('Chat fetch error (catch block):', error);
                loadingIndicator.classList.add('hidden');
                userInput.disabled = false;
                sendButton.disabled = false;
                chatError.textContent = `An error occurred while communicating with the AI: ${error.message}. Check console for details.`;
                chatError.classList.remove('hidden');
                appendMessage('AI', `Error: An unexpected network or processing error occurred during chat: ${error.message}`);
            });
    }
});

// Event listener for Enter key in user input
userInput.addEventListener('keypress', function (event) {
    if (event.key === 'Enter') {
        sendButton.click();
    }
});

// --- Automatic processing block (modified for standalone HTML) ---
// This block is for scenarios where a report might be "pre-loaded" or
// needs automatic processing on page load. For this standalone HTML,
// `isProcessingFromFlask` will be false, so this block won't execute.
// If you want to simulate this, you would manually set `isProcessingFromFlask = true;`
// and provide a dummy `filename` and `BASE_URL` for `download_report`.
if (isProcessingFromFlask) {
    console.log("Page loaded with is_processing flag. Initiating automatic report processing.");
    welcomePanel.classList.add('hidden');
    chatPanel.classList.remove('hidden');
    loadingIndicator.classList.remove('hidden');

    currentLlmMode = llmModeSelector.value || 'local'; // Ensure LLM mode is picked up from selector or defaults

    const processingLoadingMessage = document.createElement('div');
    processingLoadingMessage.className = 'message ai-message mb-4 flex items-start';
    processingLoadingMessage.innerHTML = `
        <div class="message-avatar ai mr-3"><span class="material-symbols-outlined text-white text-base">psychology</span></div>
        <div class="bg-blue-50 p-3 rounded-xl max-w-[75%]">
            <div class="flex items-center text-blue-700">
                <div class="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500 mr-2"></div>
                <p>Processing your report. Please wait...</p>
            </div>
        </div>
    `;
    chatHistory.appendChild(processingLoadingMessage);
    chatHistory.scrollTop = chatHistory.scrollHeight;

    // In a standalone HTML, `filename` would not be available from Flask context.
    // This part would need to be adjusted if you want to simulate a pre-loaded file.
    const filename = ''; // Placeholder for filename

    if (filename) {
        console.log("Fetching report for automatic processing from Flask /download_report:", `${BASE_URL}/download_report?filename=${encodeURIComponent(filename)}`);
        fetch(`${BASE_URL}/download_report?filename=${encodeURIComponent(filename)}`)
            .then(response => {
                console.log("Received response from Flask /download_report. Status:", response.status);
                if (!response.ok) {
                    return response.text().then(text => { throw new Error(`Failed to fetch file for reprocessing: ${response.statusText} - ${text}`); });
                }
                return response.blob();
            })
            .then(blob => {
                const formData = new FormData();
                const file = new File([blob], filename, { type: 'application/pdf' });
                formData.append('file', file); // FastAPI's /upload_report expects 'file'

                const uploadUrl = `${FASTAPI_BACKEND_URL}/upload_report?llm_mode=${encodeURIComponent(currentLlmMode)}`;
                console.log("Sending automatic upload request to FastAPI:", uploadUrl);
                return fetch(uploadUrl, {
                    method: 'POST',
                    body: formData
                });
            })
            .then(response => {
                console.log("Received response from FastAPI /upload_report (automatic). Status:", response.status);
                if (!response.ok) {
                    return response.json().then(err => {
                        throw new Error(err.detail || 'Upload failed');
                    });
                }
                return response.json();
            })
            .then(data => {
                console.log("FastAPI automatic upload response data:", data);
                processingLoadingMessage.remove();
                loadingIndicator.classList.add('hidden');

                if (data.error) {
                    throw new Error(data.error);
                }

                if (data.session_id) {
                    currentSessionId = data.session_id;
                }
                if (data.summary) {
                    appendMessage('AI', data.summary);
                    chatContext.push({ role: 'assistant', content: data.summary });
                    userInput.disabled = false;
                    sendButton.disabled = false;
                    console.log("Automatic report processed, summary displayed.");
                } else {
                    appendMessage('AI', 'Automatic processing completed, but no summary was returned.');
                    console.warn("FastAPI automatic upload completed without a 'summary' field.");
                }
                if (data.llm_mode) {
                     llmModeSelector.value = data.llm_mode;
                }
            })
            .catch(error => {
                console.error('Error during automatic report processing (catch block):', error);
                processingLoadingMessage.remove();
                loadingIndicator.classList.add('hidden');

                const errorMessage = document.createElement('div');
                errorMessage.className = 'message ai-message mb-4 flex items-start';
                errorMessage.innerHTML = `
                    <div class="message-avatar ai mr-3"><span class="material-symbols-outlined text-white text-base">psychology</span></div>
                    <div class="bg-red-100 p-3 rounded-xl max-w-[75%] text-red-800">
                        <p>Error: ${error.message || 'Failed to process the report automatically. Please try uploading manually.'}</p>
                    </div>
                `;
                chatHistory.appendChild(errorMessage);
                chatHistory.scrollTop = chatHistory.scrollHeight;
            });
    } else {
        console.warn("No filename found for automatic processing. Displaying message.");
        loadingIndicator.classList.add('hidden');
        const noReportMessage = document.createElement('div');
        noReportMessage.className = 'message ai-message mb-4 flex items-start';
        noReportMessage.innerHTML = `
            <div class="message-avatar ai mr-3"><span class="material-symbols-outlined text-white text-base">psychology</span></div>
            <div class="bg-gray-100 p-3 rounded-xl max-w-[75%] text-gray-700">
                <p>No report filename or session ID found for automatic processing. Please upload a new report to begin.</p>
            </div>
        `;
        chatHistory.appendChild(noReportMessage);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }
}
