from flask import Blueprint, request, jsonify

from server import db
from server._utils import generate_email_verification_token, create_response_object
from server.models import User

user_auth = Blueprint('user_authentication', __name__)


@user_auth.route('/register', methods=['POST'])
def register():
    """The registration endpoint that handles new user registration for the application"""
    user_register_data = request.json  # Get user registration information from the request body

    if not user_register_data:  # If no data found return Error 400 - Bad Request
        response_object = {  # Create the response object
            'Status': 'Failure',
            'Message': 'Incorrect Request'
        }
        return jsonify(response_object), 400

    # Extract registration information from the request payload
    username = user_register_data.get('username')
    email = user_register_data.get('email')
    password = user_register_data.get('password')

    # Process registration of new user
    # Check if a user with the same username already exists in the database
    if db.session.query(User.username).filter_by(username=username).first() is not None:
        return jsonify({'Error': 'User with the same username already exists'}), 409
    # Check if a user with the same email already exists in the database
    elif db.session.query(User.email).filter_by(email=email).first() is not None:
        return jsonify({'Error': 'User with the same email address already exists'}), 409

    new_user = User(username=username, email=email)  # Create the new user object
    new_user.create_password_hash(password=password)  # Hash & set user password

    # Generate confirmation token to be sent to the user's email address
    confirmation_token = generate_email_verification_token(new_user.email, new_user.id)  # Generate the token
   # print(confirmation_token)

    # Send the confirmation email with the token
    # TODO: Flask MAIL / SendGrid / MailGun ???

    db.session.add(new_user)  # Add new user to the database
    db.session.commit()  # Commit the changes to the database

    # Return success message with HTTP 201 - Resource created status code
    return jsonify({'Message': 'Registration successful, please check your email for verification instructions'}), 201


@user_auth.route('/login', methods=['POST'])
def login():
    """The login endpoint that handles authenticating and logging users in"""
    user_login_data = request.json  # Get the user login information from the request body

    if not user_login_data:  # If no data found return Error 400 - Bad Request
        response_object = create_response_object('Bad Request', 'Incorrect request')
        return jsonify(response_object), 400

    # Extract login information from the request payload
    username = user_login_data.get('username')
    password = user_login_data.get('password')

    # Get the user object from the database - query by username
    user = db.session.query(User).filter_by(username=username).first()

    if user is None:  # If the user does not exist return Error 404 - Not Found
        response_object = create_response_object('Not Found', 'User does not exists')
        return jsonify(response_object), 404

    if not user.is_verified:  # If the user hasn't verified their account yet return Error 401 - Unauthorized
        response_object = create_response_object('Unauthorized', 'Not verified')
        return jsonify(response_object), 401

    # Check if the user has provided the correct password for the account
    password_validated = user.validate_password_hash(password=password)

    if not password_validated:  # If the password is incorrect return  Error 401 - Unauthorized
        response_object = create_response_object('Unauthorized', 'Incorrect password')
        return jsonify(response_object), 401

    print(user)
    return jsonify({'Success': f'Successfully logged in - {user.username}'}), 200
    # TODO: Issue token and send response with HTTP 200

