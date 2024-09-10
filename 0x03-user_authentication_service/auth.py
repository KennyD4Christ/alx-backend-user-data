#!/usr/bin/env python3
"""
Authentication module for handling user registration and password hashing.
"""

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User

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
