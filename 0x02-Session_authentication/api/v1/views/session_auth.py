#!/usr/bin/env python3
"""
Module of Session Authentication views

This module provides Flask routes for handling session-based
authentication.
It includes functionality for user login and logout operations,
utilizing the User model and authentication mechanisms.

The module interacts with the database to validate user credentials and
manages session creation and destruction. It ensures proper error handling
and response formatting for various authentication scenarios.
"""

from flask import request, jsonify, abort
from models.user import User
from api.v1.views import app_views
from api.v1.app import auth
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login():
    """
    Handle user login and session creation.

    This function processes a POST request for user authentication.
    It validates the provided email and password, creates a new session
    for authenticated users, and returns the user's JSON representation
    along with a session cookie.

    Returns:
        A JSON response with user data and session cookie on successful login,
        or an error message with appropriate HTTP status code on failure.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400

    if not password:
        return jsonify({"error": "password missing"}), 400

    user_list = User.search({"email": email})
    if not user_list or len(user_list) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user = user_list[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    session_name = os.getenv("SESSION_NAME")
    response.set_cookie(session_name, session_id)
    return response


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout_user():
    """
    Handle user logout by destroying the current session.

    This function processes a DELETE request to log out the user.
    It attempts to destroy the current session associated with the request.
    If successful, it returns an empty JSON response. If the session
    destruction fails, it aborts with a 404 error.

    Returns:
        An empty JSON response with 200 status code on successful logout,
        or aborts with 404 if session destruction fails.
    """
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
