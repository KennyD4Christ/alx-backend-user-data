#!/usr/bin/env python3
"""
Module for API authentication management.
"""
from flask import request
from typing import List, TypeVar
import fnmatch


class Auth:
    """Auth class template for authentication management."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is required.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of paths that do not require
            authentication.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if path is None:
            return True

        if not excluded_paths or excluded_paths == []:
            return True

        if not path.endswith('/'):
            path += '/'

        if path in excluded_paths:
            return False

        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        # Normalize the path to ensure it ends with a slash
        normalized_path = path if path.endswith('/') else f"{path}/"

        for excluded_path in excluded_paths:
            """ Use fnmatch to compare the path with the excluded_path,
                considering wildcards
            """
            if fnmatch.fnmatch(normalized_path, excluded_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request.

        Args:
            request: The Flask request object.

        Returns:
            str: The Authorization header value or None if not present.
        """
        if request is None:
            return None

        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request.

        Args:
            request: The Flask request object.

        Returns:
            TypeVar('User'): None for now (to be implemented later).
        """
        return None
