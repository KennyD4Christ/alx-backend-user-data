#!/usr/bin/env python3
""" User module
"""
import hashlib
from datetime import datetime
from models.base import Base


class User(Base):
    """ User class
    """

    def __init__(self, *args: list, **kwargs: dict):
        """ Initialize a User instance
        """
        super().__init__(*args, **kwargs)
        self.email = kwargs.get('email')
        self._password = kwargs.get('_password')
        self.first_name = kwargs.get('first_name')
        self.last_name = kwargs.get('last_name')

    def to_json(self, for_serialization: bool = False) -> dict:
        """ Convert User instance to dictionary JSON representation """
        json_dict = super().to_json(for_serialization)
        
        # Remove _password from the dictionary if it exists
        json_dict.pop('_password', None)
        
        # Add specific User attributes
        json_dict.update({
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
        })
        
        # Format datetime objects
        for key in ['created_at', 'updated_at']:
            if isinstance(json_dict.get(key), datetime):
                json_dict[key] = json_dict[key].strftime('%Y-%m-%d %H:%M:%S')
        
        return json_dict

    @property
    def password(self) -> str:
        """ Getter of the password
        """
        return self._password

    @password.setter
    def password(self, pwd: str):
        """ Setter of a new password: encrypt in SHA256
        """
        if pwd is None or type(pwd) is not str:
            self._password = None
        else:
            self._password = hashlib.sha256(pwd.encode()).hexdigest().lower()

    def is_valid_password(self, pwd: str) -> bool:
        """ Validate a password
        """
        if pwd is None or type(pwd) is not str:
            return False
        if self.password is None:
            return False
        pwd_e = pwd.encode()
        return hashlib.sha256(pwd_e).hexdigest().lower() == self.password

    def display_name(self) -> str:
        """ Display User name based on email/first_name/last_name
        """
        if self.email is None and self.first_name is None \
                and self.last_name is None:
            return ""
        if self.first_name is None and self.last_name is None:
            return "{}".format(self.email)
        if self.last_name is None:
            return "{}".format(self.first_name)
        if self.first_name is None:
            return "{}".format(self.last_name)
        else:
            return "{} {}".format(self.first_name, self.last_name)
