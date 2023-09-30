from flask import Blueprint, request, jsonify

from server import db
from server._utils import generate_email_verification_token
from server.models import User

user_auth = Blueprint('user_authentication', __name__)


@user_auth.route('/register', methods=['POST'])
def register():
    """The registration endpoint that handles new user registration for the application"""
    user_data = request.json  # Get user registration information from the request body

    if not user_data:  # If no data found return Error 400 - Bad Request
        return jsonify({'Error': 'Incorrect Request'}), 400

    # Extract registration information from the request payload
    username = user_data.get('username')
    email = user_data.get('email')
    password = user_data.get('password')

    # Process registration of new user
    # TODO: Check if user with username / email already exists in the database
    # If user already exists return HTTP 409 - Conflict
    new_user = User(username=username, email=email)  # Create the new user object
    new_user.create_password_hash(password=password)  # Hash & set user password

    # Generate confirmation token to be sent to the user's email address
    confirmation_token = generate_email_verification_token(new_user.email, new_user.id)  # Generate the token
    print(confirmation_token)

    # Send the confirmation email with the token
    # TODO: Flask MAIL / SendGrid / MailGun ???

    db.session.add(new_user)  # Add new user to the database
    db.session.commit()  # Commit the changes to the database

    # Return success message with HTTP 201 - Resource created status code
    return jsonify({'Message': 'Registration successful, please check your email for verification instructions'}), 201


@user_auth.route('/login')
def login():
    # TODO: Implement login logic
    pass
