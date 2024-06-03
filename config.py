import os


#=====================================================
#=====================================================
#Configuração das chaves e do JWD
#=====================================================
#=====================================================


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'GJENTW;GILETJNGTWJTEG'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'your_jwt_secret_key'
