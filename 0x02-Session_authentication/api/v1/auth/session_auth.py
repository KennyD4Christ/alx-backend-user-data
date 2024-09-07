#!/usr/bin/env python3
"""SessionAuth module
"""

import uuid
from models.user import User
from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    """
    SessionAuth class that inherits from Auth.
    This will be used for session-based authentication.
    """

    # Class attribute to store session IDs with corresponding user IDs
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create a session ID for the given user_id.

        Args:
            user_id (str): The user ID for which the session is created.

        Returns:
            str: The created session ID, or None if user_id is invalid.
        """
        if user_id is None or not isinstance(user_id, str):
            return None

        # Generate a new session ID using uuid4
        session_id = str(uuid.uuid4())

        # Store the session ID and the corresponding user_id in the dictionary
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Return the user ID based on the given session ID.

        Args:
            session_id (str): The session ID to retrieve the user ID.

        Returns:
            str: The user ID associated with the session ID, or None if invalid
        """
        if session_id is None or not isinstance(session_id, str):
            return None

        # Retrieve the user_id associated with the session_id using .get()
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        Return the User instance based on the cookie value.

        Args:
            request: The HTTP request object containing the cookies.

        Returns:
            User: The User instance corresponding to the session ID,
            or None if not found.
        """
        # Retrieve the session ID from the request cookies
        # using self.session_cookie
        session_id = self.session_cookie(request)

        if not session_id:
            return None

        # Retrieve the user ID based on the session ID using
        # user_id_for_session_id
        user_id = self.user_id_for_session_id(session_id)

        if not user_id:
            return None

        # Retrieve the User instance using the user ID
        try:
            user = User.get(user_id)
        except Exception:
            return None

        return user

    def destroy_session(self, request=None):
        """
        Delete the user session (logout).
        """
        if request is None:
            return False

        # Retrieve the session ID from the cookie
        session_id = self.session_cookie(request)
        if not session_id:
            return False

        # Check if the session ID is associated with any user
        if not self.user_id_for_session_id(session_id):
            return False

        # Delete the session ID from the dictionary
        del self.user_id_by_session_id[session_id]
        return True
