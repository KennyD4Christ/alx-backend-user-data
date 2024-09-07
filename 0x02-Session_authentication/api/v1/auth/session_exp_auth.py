#!/usr/bin/env python3
"""
SessionExpAuth module
This module provides a session authentication system with expiration
functionality.
It extends the basic SessionAuth by adding a configurable session duration.
"""

from api.v1.auth.session_auth import SessionAuth
from os import getenv
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """
    SessionExpAuth class
    This class implements session authentication with an expiration mechanism.
    It inherits from SessionAuth and adds functionality to expire sessions
    after a configurable duration.
    """

    def __init__(self):
        """
        Initialize the SessionExpAuth instance.
        Sets up the session duration based on the SESSION_DURATION environment
        variable.
        """
        super().__init__()
        try:
            self.session_duration = int(getenv('SESSION_DURATION', '0'))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """
        Create a new session for the given user ID.

        Args:
            user_id (str): The ID of the user to create a session for.

        Returns:
            str: The created session ID if successful, None otherwise.
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        session_dictionary = {
            'user_id': user_id,
            'created_at': datetime.now()
        }
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """
        Retrieve the user ID associated with the given session ID,
        taking into account the session expiration.

        Args:
            session_id (str): The session ID to look up.

        Returns:
            str: The user ID if the session is valid and not expired,
            None otherwise.
        """
        if session_id is None or session_id not in self.user_id_by_session_id:
            return None

        session_dict = self.user_id_by_session_id.get(session_id)

        if self.session_duration <= 0:
            return session_dict.get('user_id')

        created_at = session_dict.get('created_at')
        if created_at is None:
            return None

        expiration_time = created_at + timedelta(seconds=self.session_duration)
        if expiration_time < datetime.now():
            return None

        return session_dict.get('user_id')
