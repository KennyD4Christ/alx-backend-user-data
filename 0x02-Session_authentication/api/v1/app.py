#!/usr/bin/env python3
"""
Module of Users views
This module provides API endpoints for user-related operations,
including viewing, creating, updating, and deleting users.
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/users', methods=['GET'], strict_slashes=False)
def view_all_users() -> str:
    """
    GET /api/v1/users
    Retrieve all User objects.

    Returns:
        str: JSON representation of a list of all User objects
    """
    all_users = [user.to_json() for user in User.all()]
    return jsonify(all_users)


@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)
def view_one_user(user_id: str = None) -> str:
    """
    GET /api/v1/users/:id
    Retrieve a specific User object by ID or the authenticated user.

    Args:
        user_id (str): The ID of the user to retrieve, or 'me' for the
        authenticated user

    Returns:
        str: JSON representation of the User object

    Raises:
        404: If the User ID doesn't exist or if 'me' is used and no
        user is authenticated
    """
    if user_id == 'me':
        if request.current_user is None:
            abort(404)
        if isinstance(request.current_user, str):
            user = User.get(request.current_user)
        else:
            user = request.current_user
        if user is None:
            abort(404)
        return jsonify(user.to_json())

    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)
    return jsonify(user.to_json())


@app_views.route('/users/<user_id>', methods=['DELETE'], strict_slashes=False)
def delete_user(user_id: str = None) -> str:
    """
    DELETE /api/v1/users/:id
    Delete a User object.

    Args:
        user_id (str): The ID of the user to delete

    Returns:
        str: Empty JSON if the User has been correctly deleted

    Raises:
        404: If the User ID doesn't exist
    """
    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)
    user.remove()
    return jsonify({}), 200


@app_views.route('/users', methods=['POST'], strict_slashes=False)
def create_user() -> str:
    """
    POST /api/v1/users/
    Create a new User object.

    JSON body:
        - email: string (required)
        - password: string (required)
        - last_name: string (optional)
        - first_name: string (optional)

    Returns:
        str: JSON representation of the newly created User object

    Raises:
        400: If the request is invalid or the user can't be created
    """
    rj = None
    error_msg = None
    try:
        rj = request.get_json()
    except Exception as e:
        rj = None
    if rj is None:
        error_msg = "Wrong format"
    if error_msg is None and rj.get("email", "") == "":
        error_msg = "email missing"
    if error_msg is None and rj.get("password", "") == "":
        error_msg = "password missing"
    if error_msg is None:
        try:
            user = User()
            user.email = rj.get("email")
            user.password = rj.get("password")
            user.first_name = rj.get("first_name")
            user.last_name = rj.get("last_name")
            user.save()
            return jsonify(user.to_json()), 201
        except Exception as e:
            error_msg = "Can't create User: {}".format(e)
    return jsonify({'error': error_msg}), 400


@app_views.route('/users/<user_id>', methods=['PUT'], strict_slashes=False)
def update_user(user_id: str = None) -> str:
    """
    PUT /api/v1/users/:id
    Update a User object.

    Args:
        user_id (str): The ID of the user to update

    JSON body:
        - last_name: string (optional)
        - first_name: string (optional)

    Returns:
        str: JSON representation of the updated User object

    Raises:
        404: If the User ID doesn't exist
        400: If the request is invalid or the user can't be updated
    """
    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)
    rj = None
    try:
        rj = request.get_json()
    except Exception as e:
        rj = None
    if rj is None:
        return jsonify({'error': "Wrong format"}), 400
    if rj.get('first_name') is not None:
        user.first_name = rj.get('first_name')
    if rj.get('last_name') is not None:
        user.last_name = rj.get('last_name')
    user.save()
    return jsonify(user.to_json()), 200
