#!/usr/bin/env python3
"""
Authentication module for handling user registration and password hashing.
"""
from db import DB
from user import User
from sqlalchemy.exc import NoResultFound
import bcrypt
import uuid


class Auth:
    """
    Auth class to interact with the authentication database.
    """

    def __init__(self) -> None:
        """
        Initialize the Auth instance with a database connection.
        """
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """
        Hashes the given password with bcrypt and returns the salted hash.

        Args:
            password (str): The password to hash.

        Returns:
            bytes: The salted hash of the password.
        """
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()  # Generate a salt
        hashed_password = bcrypt.hashpw(password_bytes, salt)
        return hashed_password

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user with the given email and password.

        Args:
            email (str): The email of the user to register.
            password (str): The password for the user.

        Returns:
            User: The newly created User object.

        Raises:
            ValueError: If a user with the given email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            # Hash the password
            hashed_password = self._hash_password(password)
            # Add the user to the database
            user = self._db.add_user(
                email=email, hashed_password=hashed_password
            )
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate user login by checking if the provided email and
        password match.

        Args:
            email (str): The email of the user to validate.
            password (str): The password to validate.

        Returns:
            bool: True if the email and password match, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            # Check if the provided password matches the stored hashed password
            return bcrypt.checkpw(
                password.encode('utf-8'), user.hashed_password
            )
        except NoResultFound:
            return False

    def _generate_uuid(self) -> str:
        """
        Generates a new UUID and returns it as a string.

        Returns:
            str: The string representation of the generated UUID.
        """
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        """
        Create a new session for the user with the provided email and return
        the session ID.

        Args:
            email (str): The email of the user to create a session for.

        Returns:
            str: The session ID for the user.

        Raises:
            ValueError: If no user is found with the provided email.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = self._generate_uuid()
            # Update user with session_id
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        Retrieves the user corresponding to the given session ID.

        Args:
            session_id (str): The session ID to search for.

        Returns:
            User: The User object associated with the session ID, or
            None if no user is found.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Updates the specified user's session ID to None.

        Args:
            user_id (int): The ID of the user whose session ID should be
            removed.
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token for the user with the given email.

        Args:
            email (str): The email of the user requesting a password reset.

        Returns:
            str: The reset token.

        Raises:
            ValueError: If no user is found with the given email.
        """
        user = self._db.find_user_by(email=email)
        if user is None:
            raise ValueError(f"No user found with email {email}")

        # Generate a new UUID for the reset token
        reset_token = str(uuid.uuid4())

        # Update the user's reset token in the database
        user.reset_token = reset_token
        self._db._session.commit()

        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the user's password using a reset token.

        Args:
            reset_token (str): The reset token for password reset.
            password (str): The new password.

        Raises:
            ValueError: If no user is found with the given reset token.
        """
        user = self._db.find_user_by(reset_token=reset_token)
        if user is None:
            raise ValueError("Invalid reset token")

        # Hash the new password
        hashed_password = self._hash_password(password)

        # Update the user's hashed password and reset token
        user.hashed_password = hashed_password
        user.reset_token = None
        self._db._session.commit()
