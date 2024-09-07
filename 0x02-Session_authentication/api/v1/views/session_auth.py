#!/usr/bin/env python3
""" Module of Session Authentication views
"""
from flask import request, jsonify, abort
from models.user import User
from api.v1.views import app_views
from api.v1.app import auth  # Import only where necessary
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login():
    """ POST /auth_session/login
    Handles session authentication for login.
    """
    # Get email and password from the form data
    email = request.form.get('email')
    password = request.form.get('password')

    # Check if email is provided
    if not email:
        return jsonify({"error": "email missing"}), 400

    # Check if password is provided
    if not password:
        return jsonify({"error": "password missing"}), 400

    # Search for the user by email
    user_list = User.search({"email": email})
    if not user_list or len(user_list) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user = user_list[0]

    # Validate the password
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # Create a new session for the user
    session_id = auth.create_session(user.id)

    # Return the user's JSON representation
    response = jsonify(user.to_json())

    # Set the session cookie
    session_name = os.getenv("SESSION_NAME")
    response.set_cookie(session_name, session_id)

    return response


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout_user():
    """
    DELETE /api/v1/auth_session/logout
    This route logs out a user by deleting their session.
    """
    # Call the destroy_session method from the auth instance
    if not auth.destroy_session(request):
        # If destroy_session returns False, abort with 404
        abort(404)

    # If session was successfully deleted, return an empty JSON response
    # with 200 status
    return jsonify({}), 200
