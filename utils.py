import logging
import os
from datetime import datetime, timedelta
from http import HTTPStatus
from time import sleep

from cryptography.fernet import Fernet
from flask import jsonify

from stores import CREDENTIAL_STORE

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


def was_created_x_seconds_ago(past_time: datetime, seconds: int) -> bool:
	"""
	Checks if a time was a certain amount of seconds ago.
	"""
	now = datetime.now()
	target_time = past_time + timedelta(seconds=seconds)
	return now >= target_time

def delete_old_unused_credentials(max_second_tolerance: int, check_interval_seconds: int):

	logging.info(f"started the task to delete unused credentials "
				 f"with the max tolerance of {max_second_tolerance}s and an interval of {check_interval_seconds}s")

	while True:
		sleep(check_interval_seconds)

		for key in list(CREDENTIAL_STORE.keys()):
			if was_created_x_seconds_ago(CREDENTIAL_STORE[key]["creation_time"], max_second_tolerance):
				result = CREDENTIAL_STORE.pop(key, None)

				if result is None:
					logging.warning(f"the create_session_id {key} and it's credentials were to be deleted because "
							 f"they were created more than {max_second_tolerance} seconds ago, but they were not found")
				else:
					logging.info(f"deleted unused create_session_id {key} and it's credentials because "
								 f"they were created more than {max_second_tolerance} seconds ago")