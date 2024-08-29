#!/usr/bin/env python3
"""
This module provides functions to hash passwords and validate them using
bcrypt.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt and return the salted, hashed password.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: A salted, hashed password.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validate if the provided password matches the hashed password.

    Args:
        hashed_password (bytes): The hashed password to be validated against.
        password (str): The plain text password to validate.

    Returns:
        bool: True if the password matches the hashed password,
        False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
