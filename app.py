from flask import Flask, render_template, jsonify, request, Response
import threading
import json
import time
import os

# Import all functions and global state from agent_logic.py
from routes.network_scanner_bp import network_scanner_bp
from routes.zap_scanner_bp import zap_scanner_bp
from routes.ssl_scanner_bp import ssl_scanner_bp
from routes.chatbot_bp import chatbot_bp

app = Flask(__name__)

# --- IMPORTANT: SET YOUR SECRET KEY HERE ---
# It should be a long, random string. For production, load this from an environment variable.
app.secret_key = 'VulnScanAI'

# --- Flask Routes ---

# Register the blueprint with a URL prefix
app.register_blueprint(network_scanner_bp, url_prefix='/network_scanner')
app.register_blueprint(zap_scanner_bp, url_prefix='/zap_scanner')
app.register_blueprint(ssl_scanner_bp, url_prefix='/ssl_scanner')
app.register_blueprint(chatbot_bp, url_prefix='/chatbot')

@app.route('/')
def index():
    """Renders the main HTML page of the application."""
    return render_template('home.html')


if __name__ == '__main__':
    # Run Flask app
    # For production, consider using a more robust WSGI server like Gunicorn or Waitress.
    # debug=True is for development only.
    app.run(host='0.0.0.0', port=5000, debug=True)