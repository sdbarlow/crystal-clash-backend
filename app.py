# app.py
from flask import Flask, jsonify, request
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token
from datetime import timedelta
from config import Config
from dotenv import load_dotenv
from sqlalchemy import text, or_
from db import db
import os
from datetime import datetime 
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS
import requests
from jwt.algorithms import RSAAlgorithm
import json
import jwt

# Import all models
from models import UserModel  # This is crucial!

APPLE_PUBLIC_KEY_URL = 'https://appleid.apple.com/auth/keys'

load_dotenv()

def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})
    app.config.from_object(Config)
    app.config.update(
        JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY'),
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(days=7),
        JWT_TOKEN_LOCATION=['headers']
    )

    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    migrate = Migrate(app, db)

    return app

app = create_app()

def get_apple_public_key(kid):
    """Fetch and cache Apple's public keys"""
    try:
        response = requests.get(APPLE_PUBLIC_KEY_URL)
        response.raise_for_status()  # Raise an error for bad status codes
        keys = response.json()['keys']
        
        # Find the key with matching kid
        for key in keys:
            if key['kid'] == kid:
                # Convert the JWK to PEM format
                public_key = RSAAlgorithm.from_jwk(json.dumps(key))
                return public_key
                
        print(f"No matching key found for kid: {kid}")
        return None
        
    except requests.RequestException as e:
        print(f"Error fetching Apple public keys: {str(e)}")
        return None
    except (KeyError, json.JSONDecodeError) as e:
        print(f"Error parsing Apple public keys: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error getting public key: {str(e)}")
        return None

def verify_apple_token(identity_token):
    """Verify the Apple identity token"""
    try:
        # Decode the JWT header to get the key ID (kid)
        headers = jwt.get_unverified_header(identity_token)
        kid = headers['kid']
        
        # Get the public key
        public_key = get_apple_public_key(kid)
        if not public_key:
            print("Could not get Apple public key")
            return None
        
        # Verify and decode the token
        decoded = jwt.decode(
            identity_token,
            public_key,
            algorithms=['RS256'],
            audience="host.exp.Exponent",  # This is the correct audience for Expo
            verify=True
        )
        
        return decoded
        
    except jwt.InvalidTokenError as e:
        print(f"Token validation error: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error verifying token: {str(e)}")
        return None

@app.route('/login', methods=['POST'])
def login():
    try:
        if not request.is_json:
            return jsonify({'error': 'Missing JSON in request'}), 400

        apple_user_data = request.get_json()
        
        if not apple_user_data:
            return jsonify({'error': 'Invalid JSON format'}), 400

        # Verify the Apple identity token and get decoded data
        identity_token = apple_user_data.get('identityToken')
        if not identity_token:
            return jsonify({'error': 'Identity token is required'}), 400
            
        decoded_token = verify_apple_token(identity_token)
        if not decoded_token:
            return jsonify({'error': 'Invalid identity token'}), 401

        # Get email from token if not in request
        email = apple_user_data.get('email') or decoded_token.get('email')
        if not email:
            return jsonify({'error': 'Could not get email from token'}), 400

        existing_user = UserModel.query.filter_by(email=email).first()

        if existing_user:
            access_token = create_access_token(
                identity=existing_user.id,
                additional_claims={
                    'email': existing_user.email,
                    'username': existing_user.username
                }
            )
            
            return jsonify({
                'message': 'User logged in successfully',
                'user_id': existing_user.id,
                'token': access_token
            })
        
        # For new users, we need the full name (only available on first sign in)
        full_name = apple_user_data.get('fullName', {})
        if full_name is None:
            full_name = {}
            
        given_name = full_name.get('givenName', '')
        family_name = full_name.get('familyName', '')
        
        username = f"{given_name} {family_name}".strip()
        if not username:
            username = email.split('@')[0]  

        new_user = UserModel(
            email=email,
            username=username,
            created_at=datetime.utcnow(),
        )

        db.session.add(new_user)
        db.session.commit()

        access_token = create_access_token(
            identity=new_user.id,
            additional_claims={
                'email': new_user.email,
                'username': new_user.username
            }
        )

        return jsonify({
            'message': 'User created successfully',
            'user_id': new_user.id,
            'token': access_token
        }), 201

    except IntegrityError as e:
        db.session.rollback()
        print(f"Database integrity error: {str(e)}")
        return jsonify({'error': 'Database constraint violation. User might already exist.'}), 400
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    
@app.route('/api/search-users', methods=['GET'])
def search_users():
    try:
        search_query = request.args.get('query', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        query = UserModel.query

        if search_query:
            search_filter = or_(
                UserModel.username.ilike(f'%{search_query}%'),
                UserModel.email.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)

        paginated_users = query.paginate(
            page=page, 
            per_page=per_page,
            error_out=False
        )

        users = [{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'bitmoji_url': user.bitmoji_url,
            'games_played': user.games_played,
            'wins': user.wins,
            'losses': user.losses
        } for user in paginated_users.items]

        return jsonify({
            'users': users,
            'total': paginated_users.total,
            'pages': paginated_users.pages,
            'current_page': page,
            'has_next': paginated_users.has_next,
            'has_prev': paginated_users.has_prev
        })

    except Exception as e:
        print(f"Search error: {str(e)}")
        return jsonify({'error': 'Failed to search users'}), 500

if __name__ == '__main__':
    app.run()