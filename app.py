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
from twilio.rest import Client
from datetime import datetime 
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS


account_sid = "AC17fabbee4f9fe04b6cdd6159b97997bf"
auth_token  = "ea9582c83f62fe28c3b170559cfb95a2"

client = Client(account_sid, auth_token)

# Import all models
from models import UserModel  # This is crucial!

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

@app.route('/login', methods=['POST'])
def login():
    try:
        # Check if the request contains JSON data
        if not request.is_json:
            return jsonify({'error': 'Missing JSON in request'}), 400

        # Get the JSON data
        apple_user_data = request.get_json()
        
        if not apple_user_data:
            return jsonify({'error': 'Invalid JSON format'}), 400

        # Get email with better error handling
        email = apple_user_data.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Check if user exists
        existing_user = UserModel.query.filter_by(email=email).first()

        if existing_user:
            # Create access token
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
        
        # Create new user with better error handling
        full_name = apple_user_data.get('fullName', {})
        given_name = full_name.get('givenName', '')
        family_name = full_name.get('familyName', '')
        
        # Create username
        username = f"{given_name} {family_name}".strip()
        if not username:
            username = email.split('@')[0]  # Fallback username from email

        new_user = UserModel(
            email=email,
            username=username,
            created_at=datetime.utcnow(),
        )

        db.session.add(new_user)
        db.session.commit()

        # Create access token for new user
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
        # Get search query and pagination parameters
        search_query = request.args.get('query', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Build the query
        query = UserModel.query

        # Add search filter if query exists
        if search_query:
            search_filter = or_(
                UserModel.username.ilike(f'%{search_query}%'),
                UserModel.email.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)

        # Execute paginated query
        paginated_users = query.paginate(
            page=page, 
            per_page=per_page,
            error_out=False
        )

        # Format response
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
    print("Models available:", UserModel.__table__)  # Debug print
    app.run(debug=True)