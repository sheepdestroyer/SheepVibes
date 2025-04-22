# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Set environment variables for non-interactive installs
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Create a non-root user and group
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin -c "App User" appuser

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY backend/requirements.txt .

# Install any needed packages specified in requirements.txt
# Use a virtual environment for better isolation (optional but good practice)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend application code into the container at /app/backend
# Ensure ownership is set before switching user if copying as root
COPY --chown=appuser:appuser backend/ /app/backend/

# Copy the frontend files (adjust if serving differently)
COPY --chown=appuser:appuser frontend/ /app/frontend/

# Copy the entrypoint script
COPY scripts/entrypoint.sh /app/scripts/entrypoint.sh
RUN chmod +x /app/scripts/entrypoint.sh

# Define the directory where the database will be stored as a volume mount point
# This directory needs to be writable by the appuser
VOLUME /app/data
# Ensure the directory exists and has correct permissions *before* switching user
# (The VOLUME instruction itself doesn't create the directory)
RUN mkdir -p /app/data && chown appuser:appuser /app/data

# Switch to the non-root user
USER appuser

# Make port 5000 available
EXPOSE 5000

# Define environment variables (can be overridden at runtime)
ENV DATABASE_PATH=/app/data/sheepvibes.db \
    UPDATE_INTERVAL_MINUTES=15 \
    FLASK_APP=backend/app.py \
    FLASK_RUN_HOST=127.0.0.1
    # Note: FLASK_DEBUG should be 0 or unset for production

# Run the entrypoint script which handles migrations and starts the app
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
# CMD is removed as ENTRYPOINT now handles the execution
