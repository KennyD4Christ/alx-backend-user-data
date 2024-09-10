#!/usr/bin/env python3
"""
Flask application to provide user registration endpoint.
"""
from flask import Flask, request, jsonify, abort, redirect, make_response
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"])
def welcome() -> str:
    """
    Welcome route that returns a JSON response with a welcome message.

    Returns:
        str: A JSON object with a welcome message.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users() -> str:
    """
    User registration route that handles the creation of a new user.

    It expects form data fields: "email" and "password".
    If the user is successfully registered, it returns a JSON response with
    the user's email and a success message.
    If the user is already registered, it returns a JSON error message with
    a 400 status code.

    Returns:
        str: A JSON object with either a success message or an error message.
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400

    try:
        # Register the user using the Auth class
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        # If user already exists, return a 400 error
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """
    Handle user login, create a session, and set a session cookie.

    Returns:
        JSON response with the email and a success message.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        if session_id:
            response = jsonify({"email": email, "message": "logged in"})
            response.set_cookie("session_id", session_id)
            return response
        else:
            abort(401)
    else:
        abort(401)


@app.route("/sessions", methods=["DELETE"])
def logout() -> tuple:
    """
    Handles user logout by destroying the session.

    Returns:
        tuple: JSON response and HTTP status code.
    """
    session_id = request.cookies.get("session_id")

    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user:
        AUTH.destroy_session(user.id)
        response = make_response(redirect("/"))
        response.delete_cookie("session_id")
        return response
    else:
        abort(403)


@app.route("/profile", methods=["GET"])
def profile() -> tuple:
    """
    Handles user profile retrieval by session ID.

    Returns:
        tuple: JSON response with user email or HTTP status code 403.
    """
    session_id = request.cookies.get("session_id")

    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'])
def reset_password():
    """Handles password reset token generation.

    Expects form data with "email" field.

    Returns:
        JSON response with email and reset token if email is registered.
        403 status code if email is not registered.
    """
    email = request.form.get('email')

    if not email:
        abort(400, description="Email is required")

    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({
            'email': email,
            'reset_token': reset_token
        }), 200
    except ValueError:
        abort(403, description="Email not registered")


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """Handle password reset requests.

    Expects form data with 'email', 'reset_token', and 'new_password'.
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    if not email or not reset_token or not new_password:
        abort(400, description="Missing required form fields")

    try:
        # Update the password using Auth object
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        # Invalid reset token
        abort(403, description="Invalid reset token")

    return jsonify({
        "email": email,
        "message": "Password updated"
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
