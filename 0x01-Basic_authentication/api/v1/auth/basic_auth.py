#!/usr/bin/env python3
"""
Module for Basic Authentication management.
"""
from typing import TypeVar
from api.v1.auth.auth import Auth
from api.v1.views.users import User
import base64


class BasicAuth(Auth):
    """BasicAuth class for basic authentication."""

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """
        Extracts the Base64 part of the Authorization header for Basic
        Authentication.

        Args:
            authorization_header (str): The Authorization header string.

        Returns:
            str: The Base64 encoded part of the Authorization header or None.
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """
        Decodes the Base64 part of the Authorization header.

        Args:
            base64_authorization_header (str): The Base64 encoded
            Authorization header.

        Returns:
            str: The decoded value as a UTF-8 string, or None if the
            input is invalid.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """
        Extracts the user email and password from the decoded Base64
        Authorization header.
        
        Args:
            decoded_base64_authorization_header (str): The decoded Base64
            Authorization header.
        
        Returns:
            tuple: A tuple containing the user email and password, or
            (None, None) if invalid.
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        email, password = decoded_base64_authorization_header.split(':', 1)
        return email, password

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """
        Returns the User instance based on email and password.

        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.

        Returns:
            User: The User instance, or None if authentication fails.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        user_list = User.search({'email': user_email})
        if not user_list:
            return None
        user = user_list[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a given request.

        Args:
            request: The request object that contains the Authorization header

        Returns:
            User: The User instance associated with the provided credentials,
            or None.
        """
        authorization_header = self.authorization_header(request)
        if authorization_header is None:
            return None
        base64_header = self.extract_base64_authorization_header(
            authorization_header
        )
        if base64_header is None:
            return None
        decoded_header = self.decode_base64_authorization_header(
            base64_header
        )
        if decoded_header is None:
            return None
        user_email, user_pwd = self.extract_user_credentials(decoded_header)
        if user_email is None or user_pwd is None:
            return None
        return self.user_object_from_credentials(user_email, user_pwd)
