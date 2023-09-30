from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()  # Instantiate the DB object
bcrypt = Bcrypt()  # Instantiate the Bcrypt object
