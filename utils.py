import logging
from http import HTTPStatus
from flask import jsonify

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


