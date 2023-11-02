import datetime
from functools import wraps

import jwt
from flask import url_for, request, jsonify

from server.settings import SECRET_KEY

VERIFICATION_TOKEN_EXP = 24  # Token expiration used for email verification (HOURS)
AUTHENTICATION_TOKEN_EXP = 31  # Token expiration used for user authentication (DAYS)


def generate_token(user_id, username=None, user_email=None, token_for=None, login=False):
    """Function to generate JSON Web Token used for verification & authentication"""
    expiration = None  # Initialize expiration variable - None

    # Set expiration based on what the token will be used for
    if token_for == 'verification':
        # Set expiration if the token is used for email verification
        expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=VERIFICATION_TOKEN_EXP)
    elif token_for == 'authentication':
        # Set expiration if the token is used for user authentication
        expiration = datetime.datetime.utcnow() + datetime.timedelta(days=AUTHENTICATION_TOKEN_EXP)

    if expiration:
        payload = {  # Define the token payload
            'user_id': user_id,
            'username': username,
            'user_email': user_email,
            'expiry': datetime.datetime.isoformat(expiration),
            'login': login
        }

        # The secret key is used to create a unique signature which then will be used to verify the token

        token = jwt.encode(payload=payload, key=SECRET_KEY, algorithm='HS256')  # Generate the token

        return token  # Return the token


def decode_token(token):
    """Function to get the payload stored in the verification token"""
    try:
        payload = jwt.decode(token, key=SECRET_KEY, algorithms=['HS256'])  # Decode the token

        payload_dict = {  # Get the information stored in the payload
            'user_id': payload['user_id'],
            'username': payload['username'],
            'user_email': payload['user_email'],
            'expiry': datetime.datetime.fromisoformat(payload['expiry']),
            'login': payload['login']
        }

        # Return 401 if token has expired
        if payload_dict['expiry'] < datetime.datetime.utcnow():
            return create_response_object('Unauthorized', 'Token has expired')

        return payload_dict

    # Handle Expired Signature and general decoding errors by sending 401
    except jwt.ExpiredSignatureError:
        return create_response_object('Unauthorized', 'Token has expired')
    except jwt.DecodeError:
        return create_response_object('Unauthorized', 'Invalid token')


def send_verification_email(email_address, token):
    """Function to send verification email to user's email address"""
    verification_url = url_for('user_authentication.verify', token=token, _external=True)
    print(verification_url)

    # TODO: Implement email API to send email to user's email address


def create_response_object(status, message):
    """Function to return a dictionary containing the status and message for the response object"""
    return {
        'Status': status,
        'Message': message
    }


def auth_required(f):
    """Decorator function to protect endpoints on the back-end that require user authentication"""
    @wraps(f)  # Invokes 'update_wrapper' to update the metadata of the returned function with the original function
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')  # Get the authorization token from the request header
        if token:
            # If token is present, decode the token to get the payload
            payload_dict = decode_token(token=token)

            # If decoding the token has failed, return error message
            if 'user_id' not in payload_dict:
                return jsonify(payload_dict), 401

            if payload_dict['login'] is True:
                # Other user information can be accessed at this point
                return f(*args, **kwargs)  # Call the original function if the token is valid and was issued at login
            else:
                # If token was not issued upon successful login (e.g.: registration), return error message
                response_object = create_response_object('Unauthorized', 'Invalid token')
                return jsonify(response_object), 401
        else:
            # If the token is missing from the request header, send a 401
            response_object = create_response_object('Unauthorized', 'Token is missing')
            return jsonify(response_object), 401

    return decorated_function
