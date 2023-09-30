from server.extensions import db, bcrypt


# Define models to represent tables in the Azure SQL Database

class User(db.Model):
    """
    The User model - defines a User object in the database
    """
    # noinspection SpellCheckingInspection
    __tablename__ = 'users'

    # Define User table columns
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, username, email):
        """Class constructor"""
        self.username = username
        self.email = email

    def __repr__(self):
        """Object representation for debugging and read queries"""
        return f'User({self.username, self.email})'

    def create_password_hash(self, password):
        """Method to encrypt plaintext password provided by the user upon signing up"""
        self.password = bcrypt.generate_password_hash(password=password)

    def validate_password_hash(self, password):
        """Method to check if password hashes are matching used to validate user upon logging in"""
        return bcrypt.check_password_hash(pw_hash=self.password, password=password)
