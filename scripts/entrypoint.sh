#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Activate the virtual environment (adjust path if needed)
# Note: In the container, the venv is at /opt/venv as per Containerfile
. /opt/venv/bin/activate

# Navigate to the backend directory for migrations
cd /app/backend
echo "Applying database migrations from $(pwd) using app 'app'..."
# Apply database migrations using python -m flask from venv
# FLASK_APP is already set as an ENV variable in the Containerfile
/opt/venv/bin/python -m flask --app app db upgrade

# Go back to the main app directory to run the application
cd /app
if [ "$FLASK_DEBUG" = "1" ] || [ "$FLASK_ENV" = "development" ]; then
    echo "Starting Flask development server from $(pwd)..."
    # Run Flask with hot reloading enabled (default in debug mode)
    exec /opt/venv/bin/python -m flask run --host=0.0.0.0 --port=5000
else
    echo "Starting Production Server (Gunicorn) from $(pwd)..."
    # Execute the main container command using gunicorn from venv
    # Using exec means the Gunicorn process replaces the shell script process
    exec /opt/venv/bin/python -m gunicorn --workers 2 --threads 4 --worker-class gthread --bind 0.0.0.0:5000 backend.app:app
fi
