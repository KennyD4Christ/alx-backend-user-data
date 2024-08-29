#!/usr/bin/env python3
"""
Module for custom logging with obfuscation, database connection,
and main function.
"""

import os
import re
import logging
import mysql.connector
from mysql.connector.connection import MySQLConnection
from typing import List, Tuple


# Define the fields considered as Personally Identifiable Information (PII)
PII_FIELDS: Tuple[str, ...] = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    # Obfuscates the specified fields in a log message.
    pattern = f"({'|'.join(fields)})=.*?(?={separator}|$)"
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class to obfuscate sensitive information in logs.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the RedactingFormatter with the specified fields.

        Args:
            fields (List[str]): List of fields to obfuscate.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        # Format the log record, obfuscating sensitive fields.
        record.msg = filter_datum(self.fields, self.REDACTION, record.msg,
                                  self.SEPARATOR)
        return super().format(record)


def get_logger() -> logging.Logger:
    """
    Creates and returns a logger named 'user_data' with a StreamHandler
    that uses RedactingFormatter to obfuscate PII fields.

    Returns:
        logging.Logger: Configured logger for user data.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    return logger


def get_db() -> MySQLConnection:
    """
    Connects to a secure database using credentials stored in environment
    variables.

    Returns:
        MySQLConnection: A connection to the MySQL database.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    database = os.getenv("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=database
    )


def main() -> None:
    """
    Main function that retrieves all rows from the users table,
    formats them using a logger, and displays each row.
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users;")
    rows = cursor.fetchall()

    logger = get_logger()

    for row in rows:
        log_message = "; ".join([f"{key}={value}" for key, value in row.items()
                                 ])
        logger.info(log_message)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
