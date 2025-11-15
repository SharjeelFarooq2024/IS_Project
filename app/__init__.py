from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app.config import DB_URI

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '1234'
    app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    from app.routes import main
    app.register_blueprint(main)

    return app
