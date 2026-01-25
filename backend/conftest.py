"""
Backend-specific pytest configuration.
This file is discovered by pytest when running from the backend directory.
"""
import os
os.environ['TESTING'] = 'true'

# Import the app after setting the environment variable
from backend.app import app, db
