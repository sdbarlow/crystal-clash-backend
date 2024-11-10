from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, 
    get_jwt_identity, verify_jwt_in_request
)
import requests
from models.user import UserModel
from db import db
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

jwt = JWTManager()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401
    return decorated

# routes/auth.py
from flask import Blueprint, request, jsonify
from datetime import timedelta

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/auth/snapchat/token', methods=['POST'])
def exchange_token():
    try:
        code = request.json.get('code')
        
        # Exchange code for Snapchat token
        snap_response = requests.post(
            'https://accounts.snapchat.com/login/oauth2/access_token',
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'client_id': os.environ.get('SNAP_CLIENT_ID'),
                'client_secret': os.environ.get('SNAP_CLIENT_SECRET'),
                'redirect_uri': os.environ.get('SNAP_REDIRECT_URI')
            }
        )
        snap_data = snap_response.json()

        # Get user info from Snapchat
        user_response = requests.get(
            'https://kit.snapchat.com/v1/me',
            headers={
                'Authorization': f"Bearer {snap_data['access_token']}"
            }
        )
        snap_user_data = user_response.json()

        # Find or create user in your database
        user = UserModel.query.filter_by(snap_id=snap_user_data['id']).first()
        if not user:
            user = UserModel(
                snap_id=snap_user_data['id'],
                username=snap_user_data.get('displayName'),
                email=snap_user_data.get('email')
            )
            db.session.add(user)
            db.session.commit()

        # Create your own JWT token
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(days=7)
        )

        return jsonify({
            'access_token': access_token,
            'snap_token': snap_data['access_token'],
            'user': {
                'id': user.id,
                'username': user.username
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

