import logging

from flask import request
from flask_socketio import SocketIO

from message_senders import send_ssh_output
from stores import CREDENTIAL_STORE, SSH_SESSION_STORE
from models.ssh_session import SSHSession
from utils import establish_ssh_connection, close_connection


def register_message_handlers(socketio: SocketIO):
	"""Used to make the message handlers known to flask."""

	@socketio.on("start-session", namespace="/ssh")
	def handle_start_session_wrapper(data):
		handle_start_session(data, socketio)

	@socketio.on("ssh-input", namespace="/ssh")
	def handle_ssh_input_wrapper(data):
		handle_ssh_input(data, socketio)

	@socketio.on("disconnect", namespace="/ssh")
	def handle_disconnect_wrapper():
		handle_disconnect(socketio)

	@socketio.on("timeout", namespace="/ssh")
	def handle_timeout_wrapper():
		handle_timeout(socketio)

	@socketio.on("resize", namespace="/ssh")
	def handle_resize_wrapper(data):
		handle_resize(data)


def handle_start_session(data, socketio: SocketIO):
	"""
	Handles the connection of a new client terminal.

	Responds to the `connect` event.

	:param data: Data passed from the client. Has `credentials_uuid`.
	"""
	flask_sid = request.sid
	credentials_uuid = data.get("credentials_uuid", None)

	if not credentials_uuid:
		logging.warning(f"[flask_sid={flask_sid}] Missing 'credentials_uuid' in data")
		return close_connection(flask_sid, socketio, "Invalid request data")

	credentials = CREDENTIAL_STORE.remove_credentials(credentials_uuid)

	if not credentials:
		logging.warning(f"[flask_sid={flask_sid}] No credentials found with credentials_uuid {credentials_uuid} in the credentials store")
		return close_connection(flask_sid, socketio, f"No credentials found for {credentials_uuid}")

	try:
		logging.info(f"[flask_sid={flask_sid}] New terminal created, switching log identification to flask_sid from credentials uuid {credentials_uuid}")
		ssh_client, ssh_channel = establish_ssh_connection(credentials, flask_sid)
		ssh_session = SSHSession(
			flask_request_sid=flask_sid,
			client=ssh_client,
			channel=ssh_channel,
		)
		SSH_SESSION_STORE.add_session(ssh_session)
		logging.info(f"[flask_sid={flask_sid}] SSH session established successfully")

		# According to https://github.com/cs01/pyxtermjs (it seems to be fixed):
		# Logging/print statements must go after this
		# If they come before, the background task never starts
		socketio.start_background_task(
			target=send_ssh_output,
			flask_sid=flask_sid,
			socketio=socketio
		)
	except ValueError as e:
		logging.exception(f"[flask_sid={flask_sid}] Failed to establish SSH connection: {e}")
		close_connection(flask_sid, socketio, f"Failed to establish an SSH connection: {e}")
	except Exception as e:
		logging.exception(f"[flask_sid={flask_sid}] Failed to establish SSH connection: {e}")
		close_connection(flask_sid, socketio, f"Failed to establish an SSH connection")


def handle_ssh_input(data, socketio: SocketIO):
	"""
	Handles input from the client terminal.

	Responds to the `ssh-input` event.

	:param data: Data passed from the client. Has `input`.
	:param socketio: The SocketIO object.
	"""
	flask_sid = request.sid
	ssh_session = SSH_SESSION_STORE.get_session(flask_sid)

	if ssh_session and ssh_session.channel.send_ready():
		user_input = data.get("input", "")

		match len(user_input):
			case 0:
				logging.debug(f"[flask_sid={flask_sid}] Empty input received")
				return
			case 1:
				logging.debug(f"[flask_sid={flask_sid}] Received input from client: {user_input} (char={ord(user_input)})")
			case _:
				logging.debug(f"[flask_sid={flask_sid}] Received input from client: {user_input} (special key)") # Space, arrows, etc...

		# Put the character in the input line buffer
		# buffer: list[int] = ssh_session.input_line_buffer
		# ssh_session.input_line_buffer = add_char_to_input_line_buffer(buffer, ord(data["input"]))
		# logging.debug(f"input buffer for {flask_sid}: {ssh_session.input_line_buffer}")

		try:
			ssh_session.channel.send(user_input)
			logging.debug(f"[flask_sid={flask_sid}] Input sent to SSH: {user_input}")
		except OSError:
			logging.error(f"[flask_sid={flask_sid}] Failed to send input to SSH. This is most likely because the socket was closed. Closing session.")
			close_connection(flask_sid, socketio, "Failed to send input to SSH")


def handle_disconnect(socketio: SocketIO):
	"""
	Handles the disconnection from the client terminal.

	Responds to the `disconnect` event.

	:param socketio: The SocketIO object.
	"""
	flask_sid = request.sid
	logging.info(f"[flask_sid={flask_sid}] Client is disconnecting, closing SSH session and socket connection...")

	close_connection(flask_sid, socketio)


def handle_timeout(socketio: SocketIO):
	"""
	Handles timeout events from the client.

	Responds to the `timeout` event.
	When the connection remains inactive (without SSH inputs or outputs) for too long, the client sends this event.

	:param socketio: The SocketIO object.
	"""
	flask_sid = request.sid
	logging.info(f"[flask_sid={flask_sid}] The connection has remained inactive for too long, closing SSH session and socket connection...")

	close_connection(flask_sid, socketio, "Timed-out, this session was inactive for too long", True)


def handle_resize(data):
	"""
	Handles terminal dimensions resizing.

	Responds to the `resize` event.

	:param data: Data passed from the client. Has `cols` and `rows`.
	"""
	flask_sid = request.sid
	ssh_session = SSH_SESSION_STORE.get_session(flask_sid)

	if ssh_session is not None:
		ssh_channel = ssh_session.channel
		if ssh_channel is not None:
			logging.debug(f"[flask_sid={flask_sid}] Resizing terminal window to cols={data['cols']}, rows={data['rows']}")
			ssh_channel.resize_pty(width=data["cols"], height=data["rows"])


