from http import HTTPStatus
from flask import jsonify

# Colors
GREEN = "\033[92m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"

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


# def is_time_older_than(past_time: datetime, seconds: int) -> bool:
# 	"""
# 	Checks if a time was a certain amount of seconds ago.
# 	"""
# 	now = datetime.now()
# 	target_time = past_time + timedelta(seconds=seconds)
# 	return now >= target_time
#
#
# def delete_old_unused_credentials(max_second_tolerance: int, check_interval_seconds: int, socketio: SocketIO):
# 	logging.info(f"Started the task to delete unused ssh sessions "
# 				 f"with the max tolerance of {max_second_tolerance}s and an interval of {check_interval_seconds}s")
#
# 	while True:
# 		sleep(check_interval_seconds)
# 		active_sessions = SSH_SESSION_STORE.list_last_active_sessions()
#
# 		for flask_sid, last_active in active_sessions.items():
# 			if is_time_older_than(last_active, max_second_tolerance):
# 				logging.info(f"[flask_sid={flask_sid}] Closing unused SSH connection")
# 				close_connection(flask_sid, socketio)
# 				logging.info(f"Removed SSH connection {flask_sid}")


