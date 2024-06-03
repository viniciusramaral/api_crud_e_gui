from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
import os

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
jwt = JWTManager(app)

from views import *

def create_database():
    if not os.path.exists('site.db'):
        with app.app_context():
            db.create_all()
            print("Database created!")

if __name__ == '__main__':
    create_database()
    app.run(debug=True)
