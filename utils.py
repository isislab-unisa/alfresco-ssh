import logging
import re

# Colors
GREEN = "\033[92m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"


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


def encrypt_credentials(credentials, cipher):
	return cipher.encrypt(str(credentials).encode())

def decrypt_credentials(encrypted_credentials, cipher):
	return eval(cipher.decrypt(encrypted_credentials).decode())