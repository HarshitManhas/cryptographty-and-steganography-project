#!/bin/bash
# Script to run the steganography application with virtual environment

# Activate virtual environment
source venv/bin/activate

# Run the application with passed arguments
python3 src/main.py "$@"
