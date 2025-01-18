import logging
import os
import re
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

def color_hostname_in_output(output) -> str:
	"""
	Color the last instance of the hostname in the output.
	This *probably* works only on standard UNIX $ format.

	:param output: The full output string
	:return: The colored output, if nothing has been found returns the same output
	"""
	# Find all occurrences
	pattern = r'(\S+@\S+)(:)(\~?[^$]+)(\$)'
	matches = list(re.finditer(pattern, output))

	if matches:
		# Find the last occurrence
		last_match = matches[-1]

		# Example for: `myuser@myserver:~/Documents/testFolder$`
		# group 1 -> `myuser@myserver` -> GREEN
		# group 2 -> `:` -> DEFAULT COLOR
		# group 3 -> `~/Documents/testFolder` -> BLUE
		# group 4 -> `$` -> DEFAULT COLOR
		colored_last_occurrence = (f"{GREEN}{last_match.group(1)}"
								   f"{RESET}{last_match.group(2)}"
								   f"{BLUE}{last_match.group(3)}"
								   f"{RESET}{last_match.group(4)}")

		# Color only the last occurrence
		output = output[:last_match.start()] + colored_last_occurrence + output[last_match.end():]

	return output


def last_input_was_x(buffer: list[int], input_to_search_for: str) -> bool:
	"""
	**UNUSED**

	Verifies if a buffer is a certain command followed by an [Enter] character.

	:param buffer: List of ASCII characters codes
	:param input_to_search_for: The input for which the function returns `True`
	:return: True if the command was found, False otherwise
	"""
	if not buffer:
		return False

	input_string = ""
	for char in buffer:
		input_string += chr(char)
		logging.debug(f"{chr(char)} ({char})")

	if (input_string == f"{input_to_search_for}\n"  # LF
			or input_string == f"{input_to_search_for}\r"  # CR
			or input_string == f"{input_to_search_for}\r\n"):  # CRLF
		logging.debug("True")
		return True

	logging.debug("False")
	return False


def add_char_to_input_line_buffer(input_line_buffer: list[int], ascii_char: int) -> list[int]:
	"""
	**UNUSED**

	Add an ascii character into the `input_line_buffer` of a session.

	If the character is a [Backspace], the last character is removed.

	If the character is an [Enter], the buffer is cleared and the new character is added.

	:param input_line_buffer: List of ASCII characters codes
	:param ascii_char: The ASCII character code to insert
	:return: The updated buffer
	"""
	if input_line_buffer is None:
		input_line_buffer = []

	# [Backspace] characters
	if ascii_char in (8, 127):
		if len(input_line_buffer) > 0:
			input_line_buffer.pop()

		return input_line_buffer

	# [Enter] characters: LF (`\n`) or CR (`\r`) or CRLF (`\n\r`)
	last_character = input_line_buffer[-1] if input_line_buffer else -1
	if last_character != -1 and last_character in (10, 13):
		return [ascii_char]

	# Avoid bad white space characters
	if ascii_char in (9, 11, 12, 14, 15, 27, 127, 263):
		return input_line_buffer

	input_line_buffer.append(ascii_char)
	return input_line_buffer


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
	return cipher.encrypt(data.encode(encoding))

def decrypt(data: bytes, encoding: str = "utf-8") -> str:
	return cipher.decrypt(data).decode(encoding)


def encrypt_credentials(credentials):
	"""
	Encrypts the hostname, the port, the username and the authentication provided in the credentials' dict.
	Leaves the creation time intact.

	:raises Exception: When no authorization method has been found in the dict
	"""
	hostname: str = credentials["hostname"]
	port: int = credentials["port"]
	username: str = credentials["username"]
	creation_time: datetime = credentials["creation_time"]

	encrypted_credentials = {
		"hostname": cipher.encrypt(hostname.encode("utf-8")),
		"port": cipher.encrypt(str(port).encode("utf-8")),
		"username": cipher.encrypt(username.encode("utf-8")),
		"creation_time": creation_time
	}

	if "ssh_key" in credentials:
		ssh_key: str = credentials["ssh_key"]
		encrypted_credentials["ssh_key"] = cipher.encrypt(ssh_key.encode("utf-8"))
	elif "password" in credentials:
		password: str = credentials["password"]
		encrypted_credentials["password"] = cipher.encrypt(password.encode("utf-8"))
	else:
		raise Exception("No SSH key or password found")

	return encrypted_credentials

def decrypt_credentials(encrypted_credentials):
	"""
	Decrypts the hostname, the port, the username and the authentication provided in the credentials' dict.
	Leaves the creation time intact.
	"""
	hostname: bytes = encrypted_credentials["hostname"]
	port: bytes = encrypted_credentials["port"]
	username: bytes = encrypted_credentials["username"]
	creation_time: datetime = encrypted_credentials["creation_time"]

	decrypted_credentials = {
		"hostname": cipher.decrypt(hostname).decode(),
		"port": int(cipher.decrypt(port).decode()),
		"username": cipher.decrypt(username).decode(),
		"creation_time": creation_time
	}

	if "ssh_key" in encrypted_credentials:
		ssh_key: bytes = encrypted_credentials["ssh_key"]
		decrypted_credentials["ssh_key"] = cipher.decrypt(ssh_key).decode()
	elif "password" in encrypted_credentials:
		password: bytes = encrypted_credentials["password"]
		decrypted_credentials["password"] = cipher.decrypt(password).decode()
	else:
		raise ValueError("No SSH key or password found")

	return decrypted_credentials


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


def create_json_response(json: dict = None, status_code: HTTPStatus = HTTPStatus.OK, error: bool = False, error_message: str = ""):
	to_send = json if json is not None else {}

	to_send["success"] = False if error else True

	if error:
		to_send["error"] = error_message

	return jsonify(to_send), status_code.value


