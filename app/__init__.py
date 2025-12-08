from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.config import DB_URI
from dotenv import load_dotenv
import os

load_dotenv() # Load environment variables from .env file

db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '1234'
    app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config.setdefault('RATELIMIT_STORAGE_URI', 'memory://')

    db.init_app(app)
    limiter.init_app(app)

    from app.routes import main
    app.register_blueprint(main)

    return app
