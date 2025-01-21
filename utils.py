import io
import logging
from http import HTTPStatus
from typing import Tuple

import paramiko
from flask import jsonify
from paramiko.channel import Channel
from paramiko.client import SSHClient
from paramiko.pkey import PKey

from models.credentials import Credentials

# Colors
GREEN = "\033[92m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"

def create_json_response(json: dict = None, status_code: HTTPStatus = HTTPStatus.OK,
						 error: bool = False, error_message: str = ""):
	"""
	Creates a JSON response for Flask applications.

	:param json: The dictionary to include in the response (default is an empty dictionary).
	:param status_code: The HTTP status code for the response (default is HTTPStatus.OK).
	:param error: Whether the response represents an error (default is False).
	:param error_message: The error message to include if error is True (default is an empty string).
	:return: A Flask JSON response and status code.
	"""
	result = json if json is not None else {} # Default as an empty dictionary

	result["success"] = not error

	if error:
		result["error"] = error_message
		logging.debug(f"Error JSON response created: {error_message}")

	logging.debug(f"JSON response created with status code {status_code}: {result}")
	return jsonify(result), status_code.value


def sanitize_json_input(data):
	"""
    Validates and sanitizes a dictionary to ensure all values are strings or integers.

    :param data: The dictionary to sanitize.
    :return: A sanitized version of the dictionary.
    :raises ValueError: If the input data or its fields are invalid.
    """
	if not isinstance(data, dict):
		logging.warning("Received invalid data type: expected dict")
		raise ValueError("Input data must be a JSON")

	sanitized_data = {}
	for key, value in data.items():
		if isinstance(value, (str, int)):
			# Transform the value into a string and clean it
			sanitized_data[key] = str(value).strip()
		else:
			logging.debug(f"Invalid field type for key '{key}': {type(value).__name__}")
			raise ValueError("The fields of the dictionary must be either strings or integers")

	logging.debug(f"Sanitized input: {sanitized_data}")
	return sanitized_data


def load_private_key(key_str) -> PKey:
	"""
	Load an SSH key from a string.

	:param key_str: The key as a string to load.
	:return: The private key in the correct format.
	:raises ValueError
	"""
	key_file = io.StringIO(key_str)
	# Check for the type of key
	for key_class in (paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key):
		try:
			return key_class.from_private_key(key_file)
		except paramiko.SSHException:
			key_file.seek(0)  # Reset the ssh key pointer position to try with another type
	raise ValueError("Invalid private key format. Accepted key formats are RSA, DSS, ECDSA, ED25519.")


def establish_ssh_connection(credentials: Credentials, flask_sid) -> Tuple[SSHClient, Channel]:
	"""
	Establishes an SSH connection using the provided credentials.

	:param credentials: The credentials to establish the SSH connection.
	:param flask_sid: The flask SID correlated to the SSH connection.
	:returns: The Paramiko SSH Client and the Paramiko SSH Channel for an interactive shell.
	:raises ValueError
	"""
	ssh_client = paramiko.SSHClient()
	ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	hostname = credentials.decrypt_hostname()
	port = int(credentials.decrypt_port())
	username = credentials.decrypt_username()

	if credentials.authentication_type == "password":
		logging.debug(f"[flask_sid={flask_sid}] Establishing SSH connection with password...")
		password = credentials.decrypt_password()
		ssh_client.connect(
		    hostname=hostname,
		    port=port,
		    username=username,
		    password=password,
		    look_for_keys=False,
		    allow_agent=False,
		)
	elif credentials.authentication_type == "ssh_key":
		logging.debug(f"[flask_sid={flask_sid}] Establishing SSH connection with SSH key...")
		private_key_file = credentials.decrypt_ssh_key()
		private_key = load_private_key(private_key_file)
		ssh_client.connect(
			hostname=hostname,
			port=port,
			username=username,
			pkey=private_key,
			look_for_keys=False,
			allow_agent=False,
		)
	else:
		raise ValueError("Invalid authentication method")

	ssh_channel = ssh_client.invoke_shell()
	ssh_channel.settimeout(0.0)
	return ssh_client, ssh_channel
