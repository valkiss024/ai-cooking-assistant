from flask import request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter

db = SQLAlchemy()  # Instantiate the DB object
bcrypt = Bcrypt()  # Instantiate the Bcrypt object
# Instantiate the Limiter object - use IP address for rate limiting
limiter = Limiter(key_func=lambda: request.remote_addr)
