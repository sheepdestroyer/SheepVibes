FROM python:3.12-slim

WORKDIR /app

# Copy requirements
COPY backend/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ .

# Create a directory for persistent data
RUN mkdir -p /data

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_DEBUG=0
ENV DATABASE_PATH=/data/sheepvibes.db

# Volume for persistent data
VOLUME ["/data"]

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
