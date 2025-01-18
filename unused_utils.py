# THIS IS SOME UNUSED CODE FROM utils.py FOR REMOVED FEATURES
# I'LL LEAVE THESE HERE IN CASE THEY COULD BE USED AGAIN
# THEY MAY NEED UPDATING

import logging
import re

from utils import GREEN, RESET, BLUE


def color_hostname_in_output(output) -> str:
	"""
	**UNUSED**

	Color the last instance of the hostname in the output.
	This works only on standard format with the $ character.

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