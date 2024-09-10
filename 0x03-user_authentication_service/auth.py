#!/usr/bin/env python3
"""
Authentication module for handling user registration and password hashing.
"""

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User
import uuid


def _hash_password(password: str) -> bytes:
    """
    Hashes the given password with bcrypt and returns the salted hash.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted hash of the password.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user with the given email and password.

        If the user already exists, a ValueError is raised.
        The password is hashed using bcrypt before
        saving the user to the database.

        Args:
            email (str): The user's email address.
            password (str): The user's plain text password.

        Returns:
            User: The newly registered user object.

        Raises:
            ValueError: If a user with the same email already exists.
        """
        try:
            # Check if the user already exists by email
            self._db.find_user_by(email=email)
            # If user exists, raise a ValueError
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            # If no user found, continue to register a new user
            # Hash the password using _hash_password
            hashed_password = _hash_password(password)
            # Add the new user to the database
            new_user = self._db.add_user(email, hashed_password)
            # Return the new User object
            return new_user

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
