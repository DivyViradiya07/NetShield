from flask import Blueprint, render_template, request, jsonify, session
import requests
import os
import uuid
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from werkzeug.utils import secure_filename

# Initialize the Flask Blueprint for chatbot-related routes
chatbot_bp = Blueprint('chatbot_bp', __name__)  # Removed url_prefix here, will add it during registration in app.py

# Create logs directory if it doesn't exist
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(log_dir, exist_ok=True)

# Configure logging
log_file = os.path.join(log_dir, 'chatbot_logs.txt')
logger = logging.getLogger('chatbot')
logger.setLevel(logging.INFO)

# Create file handler which logs even debug messages
file_handler = RotatingFileHandler(
    log_file, 
    maxBytes=1024 * 1024 * 5,  # 5MB per file
    backupCount=5,             # Keep 5 backup files
    encoding='utf-8'
)
file_handler.setLevel(logging.INFO)

# Create console handler with a higher log level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)

# Create formatter and add it to the handlers
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Log application startup
logger.info("Chatbot Blueprint initialized")

# Configure the URL of your running FastAPI chatbot backend.
# It's highly recommended to load this from an environment variable
# for flexibility in deployment (e.g., development vs. production).
# Defaulting to localhost:8000 for local development.
FASTAPI_BACKEND_URL = "http://192.168.0.156:8000"
MAX_FILE_SIZE_BYTES = 100  # 100 MB (Maximum allowed file size in bytes)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')

# ==============================
# Route for the Chatbot UI Page
# ==============================
@chatbot_bp.route('/') # This route will be '/chatbot' because of the url_prefix in app.py
def chatbot_page():
    try:
        # Check if a chatbot-specific session ID exists in the user's Flask session
        if 'chatbot_session_id' not in session:
            # If not, generate a new UUID and store it
            session['chatbot_session_id'] = str(uuid.uuid4())
            logger.info(f"New chat session started: {session['chatbot_session_id']}")
        return render_template('chatbot.html')
    except Exception as e:
        logger.error(f"Error in chatbot_page: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while loading the chatbot page"}), 500


@chatbot_bp.route('/upload_report', methods=['POST'])
def upload_report():
    try:
        if 'report_file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['report_file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        llm_mode_param = request.form.get('llm_mode', 'local') # Default to 'local' if not provided

        if file and file.filename.endswith('.pdf'):
            if file.content_length > MAX_FILE_SIZE_BYTES:
                return jsonify({'error': f'File size exceeds the limit of {MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB.'}), 413

            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)

            try:
                file.save(filepath)

                with open(filepath, 'rb') as f:
                    files_to_send = {'file': (filename, f.read(), file.content_type)}
                
                fastapi_upload_url = f"{FASTAPI_BACKEND_URL}/upload_report?llm_mode={llm_mode_param}"
                
                logger.info(f"Sending file to FastAPI ({llm_mode_param} mode): {fastapi_upload_url}")
                response = requests.post(fastapi_upload_url, files=files_to_send)
                response.raise_for_status()

                analysis_result = response.json()
                
                # --- THIS IS THE CHANGE ---
                if 'session_id' in analysis_result:
                    # Use 'chatbot_session_id' for consistency with other parts of your Flask app
                    session['chatbot_session_id'] = analysis_result['session_id'] 
                    session['current_llm_mode'] = llm_mode_param 
                    logger.info(f"Stored FastAPI session ID: {analysis_result['session_id']} with LLM mode: {llm_mode_param}")
                # --- END OF CHANGE ---

                if "error" in analysis_result:
                    return jsonify(analysis_result), response.status_code
                
                return jsonify({'message': analysis_result.get('summary', 'Report uploaded and processed.')})
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Error communicating with FastAPI backend during upload: {e}", exc_info=True)
                return jsonify({'error': f'Error communicating with the analysis service: {str(e)}'}), 500
            except Exception as e:
                logger.error(f"Error processing the uploaded file in Flask: {e}", exc_info=True)
                return jsonify({'error': f'Error processing the uploaded file: {str(e)}'}), 500
            finally:
                if os.path.exists(filepath):
                    os.remove(filepath)
        return jsonify({'error': 'Invalid file format. Only PDF files are allowed.'}), 400
    except Exception as e:
        logger.error(f"Error in upload_report: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while uploading the report"}), 500


@chatbot_bp.route('/chat', methods=['POST'])
def chat_with_ai(): # You might have named this differently
    try:
        user_message = request.json.get('message')
        # Retrieve the current session_id from Flask's session.
        # It will be None if no session exists yet, or the last known ID.
        current_flask_session_id = session.get('chatbot_session_id')

        # Prepare the payload to send to FastAPI
        payload_to_fastapi = {
            'message': user_message,
            # Send the current Flask session ID to FastAPI.
            # FastAPI will use it if it exists and is valid, or create a new one.
            'session_id': current_flask_session_id
        }

        # Make the request to your FastAPI backend's /chat endpoint
        fastapi_response = requests.post(
            f"{FASTAPI_BACKEND_URL}/chat",
            json=payload_to_fastapi
        )
        fastapi_response.raise_for_status() # This will raise an exception for 4xx/5xx responses

        fastapi_result = fastapi_response.json()

        # --- THIS IS THE CRITICAL PART: UPDATE FLASK'S SESSION ID ---
        if 'session_id' in fastapi_result and fastapi_result['session_id']:
            new_session_id_from_fastapi = fastapi_result['session_id']
            # Only update if the ID has changed (e.g., new session created by FastAPI)
            if new_session_id_from_fastapi != current_flask_session_id:
                session['chatbot_session_id'] = new_session_id_from_fastapi
                logger.info(f"Flask session ID updated to: {session['chatbot_session_id']}")

        # Return the response from FastAPI directly to the frontend
        return jsonify(fastapi_result)

    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with FastAPI chat service: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Failed to get response from chatbot: Network error or FastAPI service unreachable. ({e})'
        }), 500
    except Exception as e:
        logger.error(f"An unexpected error occurred in Flask chat route: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'An unexpected error occurred: {e}'
        }), 500


@chatbot_bp.route('/clear_chat', methods=['POST'])
def clear_chat():
    """
    Handles clearing the chat session by sending a request to the FastAPI backend.
    """
    try:
        session_id = session.get('chatbot_session_id')
        if not session_id:
            # If no session ID exists, there's nothing to clear.
            return jsonify({'status': 'error', 'message': 'No active chatbot session to clear.'}), 400

        payload = {'session_id': session_id}

        try:
            fastapi_response = requests.post(
                f"{FASTAPI_BACKEND_URL}/clear_chat",
                json=payload
            )
            # This will raise an HTTPError for 4xx and 5xx status codes
            fastapi_response.raise_for_status()
            
            # Assuming a successful response, get the JSON
            fastapi_result = fastapi_response.json()
            
            # Clear Flask session data related to chatbot
            session.pop('chatbot_session_id', None)
            session.pop('last_processed_filename', None)
            
            return jsonify(fastapi_result)
            
        except requests.exceptions.RequestException as e:
            # This catches all types of requests exceptions (e.g., connection errors, timeouts)
            logger.error(f"Error clearing chat with FastAPI chatbot service: {e}")
            return jsonify({
                'status': 'error', 
                'message': f'Failed to clear chat with chatbot: {e}. Ensure backend is running.'
            }), 500
        except Exception as e:
            # Catch any other unexpected errors
            logger.error(f"An unexpected error occurred during chat clear: {e}")
            return jsonify({
                'status': 'error', 
                'message': f'An unexpected error occurred: {e}'
            }), 500
            
    except Exception as e:
        # Final safety net for errors within the outer try block
        logger.error(f"Error in clear_chat: {str(e)}", exc_info=True)
        return jsonify({"error": "An error occurred while clearing the chat"}), 500