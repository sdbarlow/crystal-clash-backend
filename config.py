from os import environ
from dotenv import load_dotenv

load_dotenv()  # load environment variables from .env file

class Config:
    SQLALCHEMY_DATABASE_URI = environ.get('DATABASE_URL') or 'postgresql://username:password@localhost:5432/yourdatabase'
    SQLALCHEMY_TRACK_MODIFICATIONS = False