from dotenv import dotenv_values

SECRET_KEY = dotenv_values('.flaskenv').get('SECRET_KEY')
SQLALCHEMY_DATABASE_URI = dotenv_values('.flaskenv').get('SQLALCHEMY_DATABASE_URI')
SQLALCHEMY_TRACK_MODIFICATIONS = False
