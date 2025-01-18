import logging
import os
from datetime import datetime, timedelta
from http import HTTPStatus
from time import sleep
from cryptography.fernet import Fernet
from flask import jsonify
from flask_socketio import SocketIO

from message_handlers import close_connection
from stores import SSH_SESSION_STORE

# Colors
GREEN = "\033[92m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"

# Cypher
CREDENTIALS_KEY = os.getenv("CREDENTIALS_KEY", Fernet.generate_key())
cipher = Fernet(CREDENTIALS_KEY)

def create_json_response(json: dict = None, status_code: HTTPStatus = HTTPStatus.OK, error: bool = False, error_message: str = ""):
	to_send = json if json is not None else {}

	to_send["success"] = False if error else True

	if error:
		to_send["error"] = error_message

	return jsonify(to_send), status_code.value


def sanitize_input(data):
	"""
	Checks if the json data is a dictionary with string or int values.

	:raises ValueError: If the input data is wrong
	"""

	if not isinstance(data, dict):
		raise ValueError("Input data must be a json")

	sanitized_data = {}
	for key, value in data.items():
		if isinstance(value, (str, int)):
			# Transform the value into a string and clean it
			sanitized_data[key] = str(value).strip()
		else:
			raise ValueError("The fields of the json must be either strings or integers")

	return sanitized_data


def encrypt(data: str, encoding: str = "utf-8") -> bytes:
	"""Encrypts the given string using the given encoding."""
	return cipher.encrypt(data.encode(encoding))


def decrypt(data: bytes, encoding: str = "utf-8") -> str:
	"""Decrypts the given string using the given encoding."""
	return cipher.decrypt(data).decode(encoding)


def is_time_older_than(past_time: datetime, seconds: int) -> bool:
	"""
	Checks if a time was a certain amount of seconds ago.
	"""
	now = datetime.now()
	target_time = past_time + timedelta(seconds=seconds)
	return now >= target_time


def delete_old_unused_credentials(max_second_tolerance: int, check_interval_seconds: int, socketio: SocketIO):
	logging.info(f"Started the task to delete unused ssh sessions "
				 f"with the max tolerance of {max_second_tolerance}s and an interval of {check_interval_seconds}s")

	while True:
		sleep(check_interval_seconds)
		active_sessions = SSH_SESSION_STORE.list_last_active_sessions()

		for flask_sid, last_active in active_sessions.items():
			if is_time_older_than(last_active, max_second_tolerance):
				close_connection(flask_sid, socketio)
				logging.info(f"Removed SSH connection {flask_sid}")