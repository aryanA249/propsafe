"""
Sample Python Application (Hardened)
====================================
This app demonstrates safer patterns for handling input,
configuration, and runtime behavior.
"""

import json
import os
from flask import Flask, request

app = Flask(__name__)

# Read configuration from environment and use safe placeholders.
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
API_KEY = os.environ.get("API_KEY")


@app.route("/")
def home():
    """Home endpoint with safe, non-sensitive output."""
    return {
        "message": "Welcome to Secure App",
        "status": "ok",
        "config_loaded": {
            "database_password": bool(DATABASE_PASSWORD),
            "api_key": bool(API_KEY),
        },
    }


@app.route("/execute", methods=["POST"])
def execute_command():
    """
    Safe command execution endpoint.
    Allows only pre-approved commands and never invokes a shell.
    """
    payload = request.get_json(silent=True) or {}
    command_key = payload.get("cmd")

    allowed_commands = {
        "health": "Application is healthy",
        "version": "1.0.0",
        "ping": "pong",
    }

    if command_key not in allowed_commands:
        return {"error": "Unsupported command"}, 400

    return {"output": allowed_commands[command_key]}


@app.route("/deserialize", methods=["POST"])
def deserialize_data():
    """
    Safe deserialization endpoint.
    Accepts only JSON payloads and rejects unsupported types.
    """
    payload = request.get_json(silent=True) or {}
    raw_data = payload.get("payload")

    if isinstance(raw_data, (dict, list, int, float, bool)) or raw_data is None:
        return {"result": raw_data}

    if isinstance(raw_data, str):
        try:
            parsed = json.loads(raw_data)
            return {"result": parsed}
        except json.JSONDecodeError:
            return {"error": "Payload string must be valid JSON"}, 400

    return {"error": "Unsupported payload type"}, 400


@app.route("/debug")
def debug_mode():
    """
    Safe diagnostics endpoint.
    Returns non-sensitive debug status only.
    """
    return {
        "debug": False,
        "secret_data_present": bool(os.environ.get("SECRET_DATA")),
    }


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
