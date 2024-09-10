#!/usr/bin/env python3
"""
Database module for managing user data and interactions with the database.
"""
from user import Base, User
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import NoResultFound, InvalidRequestError


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds a new user to the database.

        Args:
            email (str): The email of the user.
            hashed_password (str): The hashed password of the user.

        Returns:
            User: The created User object.
        """
        new_user = User(email=email, hashed_password=hashed_password)
        # Add the user to the session
        self._session.add(new_user)
        # Commit the session to save the user to the database
        self._session.commit()
        # Return the new user
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """
        Find a user by arbitrary keyword arguments.

        Args:
            **kwargs: Arbitrary keyword arguments
            (column names and their values).

        Returns:
            User: The first matching user found.

        Raises:
            NoResultFound: If no user is found for the given filters.
            InvalidRequestError: If the query arguments are invalid.
        """
        try:
            # Use the query method to filter the User table by the provided
            # kwargs
            user = self._session.query(User).filter_by(**kwargs).one()
        except NoResultFound:
            raise NoResultFound("No user found with the specified attributes")
        except InvalidRequestError:
            raise InvalidRequestError("Invalid request arguments passed")
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Update a user's attributes and commit changes to the database.

        Args:
            user_id (int): The ID of the user to update.
            **kwargs: Arbitrary keyword arguments representing the attributes
            to update.

        Returns:
            None

        Raises:
            ValueError: If any argument passed does not correspond to a valid
            user attribute.
        """
        try:
            # Locate the user to update
            user = self.find_user_by(id=user_id)

            # Loop through the kwargs and update user attributes
            for key, value in kwargs.items():
                # Check if the key is a valid attribute of the User model
                if not hasattr(user, key):
                    raise ValueError(f"{key} is not a valid attribute of User")

                # Set the attribute on the user object
                setattr(user, key, value)

            # Commit the changes to the database
            self._session.commit()

        except NoResultFound:
            raise NoResultFound(f"No user found with id={user_id}")
