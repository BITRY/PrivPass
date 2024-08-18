#!/bin/bash
# Path to the current directory
SCRIPT_DIR="$(dirname "$0")"

# Path to your virtual environment
VENV_PATH="$SCRIPT_DIR/venv"

# Activate the virtual environment
source "$VENV_PATH/bin/activate"

# Run the password manager application
python "$SCRIPT_DIR/password_manager.py"
