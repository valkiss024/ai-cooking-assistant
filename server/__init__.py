from flask import Flask

from server.extensions import db, bcrypt
from server.routes import user_auth


def create_app(config_file='./settings.py'):
    """
    Method to set up & configure the back-end application server
    :param config_file: configuration file
    :return: server Flask object
    """

    server = Flask(__name__)  # Instantiate the Flask application server

    server.config.from_pyfile(config_file)  # Apply configuration to the server from the configuration file

    db.init_app(server)  # Initialize the database extension for the application server
    with server.app_context():
        # db.drop_all()  # Drop all existing tables in the database
        db.create_all()  # Create tables if they don't yet exist
        db.session.commit()  # Commit changes

    bcrypt.init_app(server)  # Initialize the Bcrypt extension for the application server

    server.register_blueprint(user_auth)  # Register server blueprint for authentication endpoints

    return server  # Return the application server object
