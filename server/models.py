from server.extensions import db, bcrypt


# Define models to represent tables in the Azure SQL Database

class User(db.Model):
    """
    The User model - defines a User object in the database
    """
    # noinspection SpellCheckingInspection
    __tablename__ = 'user'

    # Define User table columns
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False)
    failed_login_attempts = db.Column(db.Integer, nullable=False)
    locked_until = db.Column(db.DateTime)

    def __init__(self, username, email):
        """Class constructor"""
        self.username = username
        self.email = email
        self.is_verified = False
        self.failed_login_attempts = 0
        self.locked_until = None

    def __repr__(self):
        """Object representation for debugging and read queries"""
        return f'User({self.username, self.email})'

    def verify_user(self):
        self.is_verified = True

    def create_password_hash(self, password):
        """Method to encrypt plaintext password provided by the user upon signing up"""
        self.password = bcrypt.generate_password_hash(password=password)

    def validate_password_hash(self, password):
        """Method to check if password hashes are matching used to validate user upon logging in"""
        return bcrypt.check_password_hash(pw_hash=self.password, password=password)


class UserProfile(db.Model):
    """
    The User Profile model - defines a Profile object for users in the database
    """
    # noinspection SpellCheckingInspection
    __tablename__ = 'user_profile'

    # Define User Profile table columns
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), db.ForeignKey('user.username', ondelete='CASCADE'), nullable=False)
    first_name = db.Column(db.String(80), nullable=False, unique=False)

    # TODO: add columns to the user's profile (personal / dietary / ?)
