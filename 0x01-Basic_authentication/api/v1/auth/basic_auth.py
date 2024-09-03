#!/usr/bin/env python3
"""
Module for Basic Authentication management.
"""
from api.v1.auth.auth import Auth

class BasicAuth(Auth):
    """BasicAuth class for basic authentication."""

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """
        Extracts the Base64 part of the Authorization header for Basic Authentication.
        
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
