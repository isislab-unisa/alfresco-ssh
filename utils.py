import logging
import os
import re
from datetime import datetime, timedelta
from pprint import pprint
from time import sleep

from cryptography.fernet import Fernet
from flask_socketio import SocketIO

from stores import CREDENTIAL_STORE, CREDENTIAL_STORE_DATES

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
	Color the last instance of the hostname in the output

	:param output: The full output string
	:return: The colored output, if nothing has been found returns the same output
	"""
	pattern = r'(\S+@\S+)(:)(\~?[^$]+)(\$)'

	# Find all occurrences
	matches = list(re.finditer(pattern, output))

	if matches:
		# Find the last occurrence
		last_match = matches[-1]

		# Example for: `myuser@myserver:~/Documents/testFolder$`
		# group 1 -> `myuser@myserver`
		# group 2 -> `:`
		# group 3 -> `~/Documents/testFolder`
		# group 4 -> `$`
		colored_last_occurrence = (f"{GREEN}{last_match.group(1)}"
								   f"{RESET}{last_match.group(2)}"
								   f"{BLUE}{last_match.group(3)}"
								   f"{RESET}{last_match.group(4)}")

		# Color only the last occurrence
		output = output[:last_match.start()] + colored_last_occurrence + output[last_match.end():]

	return output


def last_input_was_exit(buffer: list[int]) -> bool:
	"""
	**UNUSED**

	Verifies if a buffer contains the command `exit` followed by an `[Enter]` character

	:param buffer: List of ASCII characters
	:return: True if the command was found, False otherwise
	"""
	if not buffer:
		return False

	input_string = ""
	for char in buffer:
		input_string += chr(char)

	for char in input_string:
		logging.debug(f"{char} ({ord(char)})")

	if (input_string == "exit\n"  # LF
			or input_string == "exit\r"  # CR
			or input_string == "exit\r\n"):  # CRLF
		logging.debug("True")
		return True

	logging.debug("False")
	return False


def add_char_to_input_line_buffer(input_line_buffer: list[int], ascii_char: int) -> list[int]:
	"""
	**UNUSED**

	Add an ascii character into the `input_line_buffer` of a session

	If the character is a backspace, the last character is removed

	If the character is a [Enter], the buffer is cleared and the new character is added

	:param input_line_buffer: List of ASCII characters
	:param ascii_char: The ASCII character to insert
	:return: The updated buffer
	"""
	if input_line_buffer is None:
		input_line_buffer = []

	# Backspace
	if ascii_char in (8, 127):
		if len(input_line_buffer) > 0:
			input_line_buffer.pop()

		return input_line_buffer

	# Enter characters: LF (`\n`) or CR (`\r`)
	last_character = input_line_buffer[-1] if input_line_buffer else -1
	if last_character != -1 and last_character in (10, 13):
		return [ascii_char]

	# Avoid bad white space characters
	if ascii_char in (9, 11, 12, 14, 15, 27, 127, 263):
		return input_line_buffer

	input_line_buffer.append(ascii_char)
	return input_line_buffer


def sanitize_input(data):
	"""Checks that the data does not contain dangerous scripts"""

	if not isinstance(data, dict):
		raise ValueError("Input data must be a dictionary")

	sanitized_data = {}
	for key, value in data.items():
		if isinstance(value, (str, int)):
			sanitized_data[key] = str(value).strip()

	return sanitized_data


def encrypt_credentials(credentials):
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
		raise ValueError("No ssh key or password found")

	return encrypted_credentials

def decrypt_credentials(encrypted_credentials):
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
		raise ValueError("No ssh key or password found")

	return decrypted_credentials


def was_created_x_seconds_ago(past_time: datetime, seconds: int) -> bool:
	now = datetime.now()
	target_time = past_time + timedelta(seconds=seconds)
	return now >= target_time

def delete_old_unused_credentials(max_second_tolerance: int, check_interval_seconds: int):
	logging.info("Started the delete_old_unused_credentials task")

	while True:
		sleep(check_interval_seconds)

		for key in list(CREDENTIAL_STORE.keys()):
			if was_created_x_seconds_ago(CREDENTIAL_STORE[key]["creation_time"], max_second_tolerance):
				if key in CREDENTIAL_STORE: # Check if the key is still in the credential store
					del CREDENTIAL_STORE[key]
					logging.info(f"Deleted unused create_session_id {key} and it's credentials because "
								 f"they were created more than {max_second_tolerance} seconds ago")