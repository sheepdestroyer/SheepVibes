import jwt
import datetime
from flask import Blueprint, request, jsonify, current_app
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPTokenAuth
from .models import db, User # Assuming User model is in models.py

# Initialize extensions
bcrypt = Bcrypt()
token_auth = HTTPTokenAuth(scheme='Bearer')

auth_bp = Blueprint('auth', __name__)

# Configuration for JWT
# In a real app, get this from app.config
JWT_SECRET_KEY = 'your-secret-key' # TODO: Move to app config
JWT_EXPIRATION_DELTA = datetime.timedelta(hours=1)

def hash_password(password):
    """Hashes a password using bcrypt."""
    return bcrypt.generate_password_hash(password).decode('utf-8')

def verify_password(hashed_password, password):
    """Verifies a password against a bcrypt hash."""
    return bcrypt.check_password_hash(hashed_password.encode('utf-8'), password)

def generate_token(user_id):
    """Generates a JWT for a given user_id."""
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + JWT_EXPIRATION_DELTA
    }
    token = jwt.encode(payload, current_app.config.get('SECRET_KEY', JWT_SECRET_KEY), algorithm='HS256')
    return token

def verify_token(token):
    """Verifies a JWT and returns the payload if valid, otherwise None."""
    try:
        payload = jwt.decode(token, current_app.config.get('SECRET_KEY', JWT_SECRET_KEY), algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

@token_auth.verify_token
def verify_auth_token_callback(token):
    """
    Callback for HTTPTokenAuth to verify a token.
    Returns the User object if the token is valid and user exists, else None.
    """
    payload = verify_token(token)
    if payload and 'user_id' in payload:
        user = db.session.get(User, payload['user_id'])
        return user
    return None

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password required'}), 400

    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_pw = hash_password(password)
    new_user = User(username=username, password_hash=hashed_pw)

    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error registering user: {e}")
        return jsonify({'message': 'Registration failed due to server error'}), 500

    return jsonify({'message': 'User registered successfully'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password required'}), 400

    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if not user or not verify_password(user.password_hash, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    token = generate_token(user.id)
    return jsonify({'token': token}), 200
