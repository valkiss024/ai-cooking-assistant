from flask import Blueprint, request, jsonify

from server import db, limiter
from server._utils import generate_token, create_response_object, send_verification_email, \
    decode_token, auth_required
from server.models import User
from server.settings import RATE_LIMIT

user_auth = Blueprint('user_authentication', __name__)


@limiter.limit(RATE_LIMIT)
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
        return jsonify({'Error': 'User with the same username or email address already exists'}), 409
    # Check if a user with the same email already exists in the database
    elif db.session.query(User.email).filter_by(email=email).first() is not None:
        return jsonify({'Error': 'User with the same username or email address already exists'}), 409

    new_user = User(username=username, email=email)  # Create the new user object
    new_user.create_password_hash(password=password)  # Hash & set user password

    db.session.add(new_user)  # Add new user to the database
    db.session.commit()  # Commit the changes to the database

    # Generate confirmation token to be sent to the user's email address
    verification_token = generate_token(user_id=new_user.id, username=new_user.username, user_email=new_user.email,
                                        token_for='verification')  # Generate the verification token

    if not verification_token:
        # Return error message if token generation fails
        return jsonify({'Message': 'Something went wrong issuing verification token'}), 500

    # Send the confirmation email with the token
    send_verification_email(email_address=new_user.email, token=verification_token)
    # TODO: Flask MAIL / SendGrid / MailGun ???

    # Return success message with HTTP 201 - Resource created status code
    return jsonify({'Message': 'Registration successful, please check your email for verification instructions'}), 201


@limiter.limit(RATE_LIMIT)
@user_auth.route('/login', methods=['POST'])
def login():
    """The login endpoint that handles authenticating and logging users in"""

    # TODO: Add check for Authorization header if contains token to authenticate user - if successfully authenticated
    #  skip the rest of the login logic and proceed logging the user in

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
        response_object = create_response_object('Unauthorized', 'Incorrect username or password')
        return jsonify(response_object), 401

    # Check if the user has provided the correct password for the account
    password_validated = user.validate_password_hash(password=password)

    if not password_validated:  # If the password is incorrect return  Error 401 - Unauthorized
        response_object = create_response_object('Unauthorized', 'Incorrect username or password')
        return jsonify(response_object), 401

    if not user.is_verified:  # If the user hasn't verified their account yet return Error 401 - Unauthorized
        response_object = create_response_object('Unauthorized', 'Not verified')
        return jsonify(response_object), 401

    # Generate authentication token (issued then stored on client side - used to authenticate current user)
    authentication_token = generate_token(user_id=user.id, username=user.username, user_email=user.email,
                                          token_for='authentication', login=True)

    if not authentication_token:
        # Return error message if token generation fails
        return jsonify({'Message': 'Something went wrong issuing authentication token'}), 500

    # Return success message & authentication token
    return jsonify({'Success': f'Successfully logged in - {user.username}', 'Token': authentication_token}), 200


@limiter.limit(RATE_LIMIT)
@user_auth.route('/verify/<token>', methods=['GET'])
def verify(token):
    """Verification endpoint that handles the confirmation of token and updates the user's status to 'verified'"""
    # Call the helper function to decode email verification token
    token_payload = decode_token(token=token)

    # If user_id is not in payload then an error occurred during decoding the token
    if 'user_id' not in token_payload:
        return jsonify(token_payload), 401

    # Get the user object from the database - query by user id
    user = db.session.query(User).filter_by(id=token_payload['user_id']).first()

    if user is None:  # If the user does not exist return Error 404 - Not Found
        response_object = create_response_object('Not Found', 'User does not exists')
        return jsonify(response_object), 404

    user.verify_user()  # Set the user's 'is_verified' flag to True
    db.session.commit()  # Commit the changes made to the user object in the database

    response_object = create_response_object('Success', f'Account for {user.username} has been verified successfully')

    return jsonify(response_object), 200  # Return success message


# ----------------------------------------------------------TEST------------------------------------------------------
@limiter.limit(RATE_LIMIT)
@user_auth.route('/test/', methods=['GET'])
@auth_required
def test():
    return jsonify({'Message': 'You are authorized to access this page'})
