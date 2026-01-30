# Use an official Python runtime as a parent image
FROM python:3.14-slim

# Set environment variables to prevent Python from writing .pyc files and to run in unbuffered mode
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Create a secure, non-root system user with a non-login shell
RUN useradd --system --create-home --shell /bin/nologin --user-group appuser

# Use a virtual environment for better isolation (optional but good practice)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY backend/requirements.txt .

# Install dependencies into the virtual environment
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend application code into the container at /app/backend
COPY --chown=appuser:appuser backend/ /app/backend/

# Copy the frontend files (adjust if serving differently)
COPY --chown=appuser:appuser frontend/ /app/frontend/

# Copy the entrypoint script & Make it script executable
COPY --chown=appuser:appuser scripts/entrypoint.sh /app/scripts/entrypoint.sh

# Ensure the data directory exists and that files have correct permissions *before* switching user
# (The VOLUME instruction itself doesn't create the directory)
RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app && \
    chmod +x /app/scripts/entrypoint.sh

# Switch to the non-root user
USER appuser

# Make port 5000 available
EXPOSE 5000

# Define environment variables (can be overridden at runtime)
ENV DATABASE_PATH=/app/data/sheepvibes.db \
    UPDATE_INTERVAL_MINUTES=15 \
    FLASK_APP=backend.app \
    PYTHONPATH=/app \
    FLASK_RUN_HOST=0.0.0.0
# Note: FLASK_DEBUG should be 0 or unset for production

# Run the entrypoint script which handles migrations and starts the app
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
