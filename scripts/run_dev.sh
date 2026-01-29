#!/bin/bash

# Navigate to the backend directory relative to the script's location
# Get the directory where the script resides
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
# Navigate to the backend directory
cd "$SCRIPT_DIR/../backend" || exit 1

# Check for virtual environment and activate it
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
  echo "Error: Virtual environment directory '$VENV_DIR' not found in backend/."
  echo "Please create it and install dependencies first:"
  echo "  cd backend"
  echo "  python -m venv $VENV_DIR"
  echo "  source $VENV_DIR/bin/activate  # (or appropriate activation command for your shell)"
  echo "  pip install --upgrade pip"
  echo "  pip install -r requirements.txt -r requirements-dev.txt"
  echo "  cd .."
  exit 1
fi

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Check if Redis server is running by using the installed 'redis' Python package
echo "Checking Redis connection..."
if ! python -c "import redis; redis.Redis(decode_responses=True).ping()" &> /dev/null; then
    echo "Error: Cannot connect to Redis server. Is it running?"
    echo "Please start Redis (e.g., 'podman run -d -p 6379:6379 redis:alpine') before running the development server."
    deactivate
    exit 1
fi
echo "Redis connection successful."

# Check if Flask is installed within the virtual environment
if ! pip show flask &> /dev/null; then
  echo "Error: 'flask' module not found in the virtual environment."
  echo "Please ensure dependencies are installed:"
  echo "  (Virtual environment should be active)"
  echo "  pip install -r backend/requirements.txt -r backend/requirements-dev.txt"
  # Deactivate before exiting
  deactivate
  exit 1
fi

# Set Flask environment variables for development
export FLASK_APP=app.py
export FLASK_DEBUG=1 # Enable debug mode (reloader and debugger)

# Apply database migrations
echo "Applying database migrations..."
python -m flask db upgrade

# Run the Flask development server
echo "Starting Flask development server on http://0.0.0.0:5000 (Press CTRL+C to stop)"
# Use python -m flask run to ensure it uses the venv's flask
python -m flask run --host=0.0.0.0 --port=5000

# Deactivate virtual environment upon exit (triggered by CTRL+C or server stop)
echo "Flask server stopped. Deactivating virtual environment."
deactivate
