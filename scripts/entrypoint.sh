#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Activate the virtual environment (adjust path if needed)
# Note: In the container, the venv is at /opt/venv as per Containerfile
. /opt/venv/bin/activate

# Navigate to the backend directory where Flask app and migrations are
cd /app/backend

echo "Applying database migrations..."
# Apply database migrations using absolute path to flask in venv
# FLASK_APP is already set as an ENV variable in the Containerfile
/opt/venv/bin/flask db upgrade

echo "Starting Flask application..."
# Execute the main container command using absolute path to flask in venv
# Using exec means the Flask process replaces the shell script process
exec /opt/venv/bin/flask run
