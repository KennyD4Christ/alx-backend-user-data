#!/usr/bin/env python3
"""
SessionDBAuth module
This module provides a session authentication system that stores session
data in a database.
It extends the functionality of SessionExpAuth by persisting sessions
across application restarts.
"""

from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession
from models.user import User
from datetime import datetime, timedelta


class SessionDBAuth(SessionExpAuth):
    """
    SessionDBAuth class
    This class implements session authentication with database storage.
    It inherits from SessionExpAuth and overrides methods to use database
    storage instead of in-memory storage for session data.
    """

    def create_session(self, user_id=None):
        """
        Create and store a new session for the given user ID.

        Args:
            user_id (str): The ID of the user to create a session for.

        Returns:
            str: The created session ID if successful, None otherwise.
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        user_session = UserSession(user_id=user_id, session_id=session_id)
        user_session.save()
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """
        Retrieve the user ID associated with the given session ID.

        Args:
            session_id (str): The session ID to look up.

        Returns:
            str: The user ID if the session is valid, None otherwise.
        """
        if session_id is None:
            return None

        UserSession.load_from_file()
        user_sessions = UserSession.search({'session_id': session_id})
        if not user_sessions:
            return None

        user_session = user_sessions[0]

        if self.session_duration <= 0:
            return user_session.user_id

        created_at = user_session.created_at
        if created_at is None:
            return None

        expiration_time = created_at + timedelta(seconds=self.session_duration)
        if expiration_time < datetime.utcnow():
            return None

        return user_session.user_id

    def destroy_session(self, request=None):
        """
        Destroy the session associated with the given request.

        Args:
            request: The request object containing the session to be destroyed.

        Returns:
            bool: True if the session was successfully destroyed,
            False otherwise.
        """
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False

        UserSession.load_from_file()
        user_sessions = UserSession.search({'session_id': session_id})
        if user_sessions:
            user_sessions[0].remove()
            return True

        return False

    def current_user(self, request=None):
        """
        Retrieve the User instance associated with the current request.

        Args:
            request: The request object to retrieve the current user for.

        Returns:
            User: The User instance if a valid session exists, None otherwise.
        """
        session_id = self.session_cookie(request)
        if session_id is None:
            return None

        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return None

        return User.get(user_id)
