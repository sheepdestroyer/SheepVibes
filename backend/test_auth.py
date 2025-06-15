import pytest
import json
import os

# Ensure backend package is discoverable
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import app, db
from backend.models import User
from backend.auth import bcrypt, generate_token # Use bcrypt from auth.py directly

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['BCRYPT_LOG_ROUNDS'] = 4
    app.config['WTF_CSRF_ENABLED'] = False
    app._got_first_request = False # Reset before potential re-init

    # Force re-initialization of db with test configuration
    if 'sqlalchemy' in app.extensions:
        del app.extensions['sqlalchemy']
    db.init_app(app)

    # bcrypt from backend.auth is used, which is initialized with app in app.py.
    # Ensure app.config['BCRYPT_LOG_ROUNDS'] is picked up if bcrypt instance uses it.
    # If bcrypt_auth (the app's instance) is different or needs reconfig:
    # from backend.auth import bcrypt as auth_bcrypt_instance
    # auth_bcrypt_instance.init_app(app) # Or similar if needed

    with app.app_context():
        db.create_all()

    test_client = app.test_client()

    yield test_client

    with app.app_context():
        db.session.remove()
        db.drop_all()

def test_register_user(client):
    """Test user registration."""
    # Successful registration
    response = client.post('/api/auth/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 201
    assert response.json['message'] == 'User registered successfully'

    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        assert user is not None
        assert user.username == 'testuser'
        assert bcrypt.check_password_hash(user.password_hash, 'testpassword')

    # Registration with existing username
    response = client.post('/api/auth/register', json={
        'username': 'testuser',
        'password': 'anotherpassword'
    })
    assert response.status_code == 400
    assert response.json['message'] == 'Username already exists'

    # Registration with missing username
    response = client.post('/api/auth/register', json={
        'password': 'testpassword'
    })
    assert response.status_code == 400
    assert response.json['message'] == 'Username and password required'

    # Registration with missing password
    response = client.post('/api/auth/register', json={
        'username': 'testuser2'
    })
    assert response.status_code == 400
    assert response.json['message'] == 'Username and password required'

def test_login_user(client):
    """Test user login."""
    # First, register a user
    client.post('/api/auth/register', json={
        'username': 'loginuser',
        'password': 'loginpassword'
    })

    # Login with correct credentials
    response = client.post('/api/auth/login', json={
        'username': 'loginuser',
        'password': 'loginpassword'
    })
    assert response.status_code == 200
    assert 'token' in response.json
    assert response.json['token'] is not None

    # Login with incorrect password
    response = client.post('/api/auth/login', json={
        'username': 'loginuser',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert response.json['message'] == 'Invalid username or password'

    # Login with non-existent user
    response = client.post('/api/auth/login', json={
        'username': 'nonexistentuser',
        'password': 'password'
    })
    assert response.status_code == 401
    assert response.json['message'] == 'Invalid username or password'

# Note: Testing token verification via a protected endpoint is better suited for test_app.py
# where actual endpoints are tested with authorization headers.
# A direct test of generate_token/verify_token could be added here if they were complex,
# but their primary validation comes from successful use in login and protected routes.

# Example of how you might test generate_token and verify_token directly (optional)
def test_jwt_utilities(client): # client fixture to ensure app_context and SECRET_KEY
    """Test JWT generation and verification functions directly."""
    with app.app_context(): # Required for current_app.config
        user = User(username='tokenuser', password_hash=bcrypt.generate_password_hash('tokenpass').decode('utf-8'))
        db.session.add(user)
        db.session.commit()

        token = generate_token(user.id)
        assert token is not None

        from backend.auth import verify_token # Import verify_token from auth.py
        payload = verify_token(token)
        assert payload is not None
        assert payload['user_id'] == user.id

        # Test with an invalid token
        invalid_token = token + "invalidpart"
        payload_invalid = verify_token(invalid_token)
        assert payload_invalid is None

        # Test with an expired token (requires mocking datetime or more complex setup)
        # For now, this basic validation is sufficient here.

    # Clean up user
    with app.app_context():
        db.session.delete(user)
        db.session.commit()
