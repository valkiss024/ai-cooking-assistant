import datetime
import jwt
from dotenv import dotenv_values

TOKEN_EXPIRATION = 24


def generate_email_verification_token(user_email, user_id):
    """Function to generate JSON Web Token to send to user in email verification"""
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRATION)  # Set token expiration

    payload = {  # Define the token payload
        'email': user_email,
        'user_id': user_id,
        'expiry': expiration
    }

    secret_key = dotenv_values('.flaskenv').get('SECRET_KEY')  # Get the secret key for the application server
    # The secret key is used to create a unique signature which then will be used to verify the token

    token = jwt.encode(payload=payload, key=secret_key)  # Generate the token

    return token  # Return the token
