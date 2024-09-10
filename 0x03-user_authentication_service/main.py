#!/usr/bin/env python3
"""
This module contains functions to test a user authentication service.

It interacts with a Flask application to test user registration, login, profile
access, logout, password reset, and password update functionalities.
Each function performs a specific operation and validates the response using
assertions.
"""

import requests


BASE_URL = "http://127.0.0.1:5000"


def register_user(email: str, password: str) -> None:
    """
    Registers a new user in the system.

    Args:
        email (str): The email of the user to register.
        password (str): The password of the user to register.

    Raises:
        AssertionError: If the server response is not 201 (created) or the
        expected payload is incorrect.
    """
    response = requests.post(
        f"{BASE_URL}/users", data={"email": email, "password": password}
    )
    assert response.status_code == 201, \
        f"Expected 201, got {response.status_code}"
    assert response.json() == {"email": email, "message": "user created"}, \
        f"Unexpected response: {response.json()}"


def log_in_wrong_password(email: str, password: str) -> None:
    """
    Attempts to log in with an incorrect password and checks for failure.

    Args:
        email (str): The email of the user attempting to log in.
        password (str): The incorrect password.

    Raises:
        AssertionError: If the server response is not 401 (Unauthorized).
    """
    response = requests.post(
        f"{BASE_URL}/sessions", data={"email": email, "password": password}
    )
    assert response.status_code == 401, \
        f"Expected 401, got {response.status_code}"


def log_in(email: str, password: str) -> str:
    """
    Logs in a user with valid credentials and retrieves the session ID.

    Args:
        email (str): The email of the user logging in.
        password (str): The password of the user.

    Returns:
        str: The session ID from the server response.

    Raises:
        AssertionError: If the login is unsuccessful or session ID is missing.
    """
    response = requests.post(
        f"{BASE_URL}/sessions", data={"email": email, "password": password}
    )
    assert response.status_code == 200, \
        f"Expected 200, got {response.status_code}"
    assert "session_id" in response.cookies, "No session_id cookie found"
    return response.cookies["session_id"]


def profile_unlogged() -> None:
    """
    Tries to access the user profile without being logged in and expects a
    403 error.

    Raises:
        AssertionError: If the server response is not 403 (Forbidden).
    """
    response = requests.get(f"{BASE_URL}/profile")
    assert response.status_code == 403, \
        f"Expected 403, got {response.status_code}"


def profile_logged(session_id: str) -> None:
    """
    Accesses the user profile while logged in.

    Args:
        session_id (str): The session ID of the logged-in user.

    Raises:
        AssertionError: If the server response is not 200 (OK) or if the
        email is not returned.
    """
    cookies = {"session_id": session_id}
    response = requests.get(f"{BASE_URL}/profile", cookies=cookies)
    assert response.status_code == 200, \
        f"Expected 200, got {response.status_code}"
    assert "email" in response.json(), \
        f"Unexpected response: {response.json()}"


def log_out(session_id: str) -> None:
    """
    Logs out a user by destroying the session.

    Args:
        session_id (str): The session ID of the logged-in user.

    Raises:
        AssertionError: If the server response is not 200 (OK).
    """
    cookies = {"session_id": session_id}
    response = requests.delete(
        f"{BASE_URL}/sessions", cookies=cookies
    )
    assert response.status_code == 200, \
        f"Expected 200, got {response.status_code}"


def reset_password_token(email: str) -> str:
    """
    Requests a password reset token for a user.

    Args:
        email (str): The email of the user requesting a password reset.

    Returns:
        str: The password reset token.

    Raises:
        AssertionError: If the server response is not 200 (OK) or if the
        reset token is missing.
    """
    response = requests.post(
        f"{BASE_URL}/reset_password", data={"email": email}
    )
    assert response.status_code == 200, \
        f"Expected 200, got {response.status_code}"
    return response.json()["reset_token"]


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """
    Resets the user's password using a reset token.

    Args:
        email (str): The email of the user updating their password.
        reset_token (str): The reset token to validate the password reset.
        new_password (str): The new password for the user.

    Raises:
        AssertionError: If the server response is not 200 (OK) or the expected
        payload is incorrect.
    """
    data = {"email": email, "reset_token": reset_token,
            "new_password": new_password}
    response = requests.put(
        f"{BASE_URL}/reset_password", data=data
    )
    assert response.status_code == 200, \
        f"Expected 200, got {response.status_code}"
    assert response.json() == {"email": email,
                               "message": "Password updated"}, \
        f"Unexpected response: {response.json()}"


# Test case
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

if __name__ == "__main__":
    """
    Main script that executes the test flow for user authentication service.
    """
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
