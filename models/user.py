# models/user.py
from db import db
from datetime import datetime

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    snap_id = db.Column(db.String(80), unique=True, nullable=True)  # Snapchat's user ID
    username = db.Column(db.String(80))
    apple_user_id = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False) 
    bitmoji_url = db.Column(db.String(255), nullable=True)  # Optional: store Bitmoji avatar URL
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Game related fields (optional - add whatever you need for your game)
    games_played = db.Column(db.Integer, default=0)
    wins = db.Column(db.Integer, default=0)
    losses = db.Column(db.Integer, default=0)