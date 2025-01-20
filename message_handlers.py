import io
import logging
import paramiko

from flask import request
from flask_socketio import SocketIO, disconnect

from message_senders import send_ssh_output
from stores import CREDENTIAL_STORE, SSH_SESSION_STORE
from models.ssh_session import SSHSession
from utils import RED, RESET


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

	EVENT: `connect`
	"""
	flask_sid = request.sid
	credentials_uuid = data.get("credentials_uuid")

	if not credentials_uuid:
		logging.error(f"[flask_sid={flask_sid}] Missing 'credentials_uuid' in data")
		return close_connection(flask_sid, socketio, "Invalid request data")

	credentials = CREDENTIAL_STORE.remove_credentials(credentials_uuid)
	logging.debug(f"[flask_sid={flask_sid}] Credentials with credentials_uuid {credentials_uuid} removed from credentials store")

	if not credentials:
		logging.warning(f"[flask_sid={flask_sid}] No credentials found with credentials_uuid {credentials_uuid}")
		return close_connection(flask_sid, socketio, f"No credentials found for {credentials_uuid}")

	try:
		logging.info(f"[flask_sid={flask_sid}] New client connected with credentials_uuid {credentials_uuid}")

		hostname = credentials.decrypt_hostname()
		port = credentials.decrypt_port()
		username = credentials.decrypt_username()

		# Create the SSH client and connect to remote SSH server
		ssh_client = paramiko.SSHClient()
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		if credentials.authentication_type == "password":
			# Connect with password
			logging.info(f"[flask_sid={flask_sid}] Connecting to SSH server with password...")
			ssh_client.connect(
				hostname=hostname,
				port=port,
				username=username,
				password=credentials.decrypt_password(),
				look_for_keys=False,
				allow_agent=False,
			)
		elif credentials.authentication_type == "ssh_key":

			def load_private_key(key_str):
				"""
				Automatically identifies the type of ssh key.
				:raises ValueError
				"""
				key_file = io.StringIO(key_str)
				for key_class in (paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key):
					try:
						return key_class.from_private_key(key_file)
					except paramiko.SSHException:
						key_file.seek(0)  # Reset the ssh key pointer position to try with another type
				raise ValueError("Key format not valid (RSA, DSS, ECDSA, ED25519).")

			private_key_file = credentials.decrypt_ssh_key()
			private_key = load_private_key(private_key_file)

			# Connect with SSH Key
			logging.info(f"[flask_sid={flask_sid}] Connecting to SSH server with SSH Key...")
			ssh_client.connect(
				hostname=hostname,
				port=port,
				username=username,
				pkey=private_key,
				look_for_keys=False,
				allow_agent=False,
			)
		else:
			raise ValueError("No valid authentication method provided")

		# Open an interactive SSH session
		ssh_channel = ssh_client.invoke_shell()
		ssh_channel.settimeout(0.0)

		ssh_session = SSHSession(
			flask_request_sid=flask_sid,
			client=ssh_client,
			channel=ssh_channel,
			credentials=credentials,
		)

		SSH_SESSION_STORE.add_session(ssh_session)

		# According to https://github.com/cs01/pyxtermjs (it seems to be fixed):
		# Logging/print statements must go after this
		# If they come before, the background task never starts
		socketio.start_background_task(
			target=send_ssh_output,
			flask_sid=flask_sid,
			socketio=socketio
		)

		if credentials.authentication_type == "password":
			logging.info(f"[flask_sid={flask_sid}] SSH session successfully established with password")
		else:
			logging.info(f"[flask_sid={flask_sid}] SSH session successfully established with SSH key")
	except Exception as e:
		logging.warning(f"[flask_sid={flask_sid}] Failed to establish an SSH connection: {e}")
		socketio.emit("ssh-output", {"output": f"{RED}Failed to establish an SSH connection: {e}{RESET}"}, namespace="/ssh", to=flask_sid)
		close_connection(flask_sid, socketio)


def handle_ssh_input(data, socketio: SocketIO):
	"""
	Reads the input (one character) from the client terminal and sends it to the ssh terminal.

	EVENT: `ssh-input`
	"""
	flask_sid = request.sid
	ssh_session = SSH_SESSION_STORE.get_session(flask_sid)

	if ssh_session is not None:
		ssh_channel = ssh_session.channel
		if ssh_channel is not None and ssh_channel.send_ready():
			if len(data["input"]) == 1:
				logging.debug(f"[flask_sid={flask_sid}] Received input from client terminal: {data['input']} ({ord(data['input'])})")

			# Put the character in the input line buffer
			#buffer: list[int] = ssh_session.input_line_buffer
			#ssh_session.input_line_buffer = add_char_to_input_line_buffer(buffer, ord(data["input"]))
			#logging.debug(f"input buffer for {flask_sid}: {ssh_session.input_line_buffer}")

			else:
				logging.debug(f"[flask_sid={flask_sid}] Received input from client terminal: {data['input']} (special key)")

			try:
				ssh_channel.send(data["input"])
			except OSError:
				logging.debug(f"[flask_sid={flask_sid}] Tried to send data to a closed socket")
				close_connection(flask_sid, socketio)

def handle_disconnect(socketio: SocketIO):
	"""
	Handles the `disconnect` event from the client terminal.

	EVENT: `disconnect`
	"""
	flask_sid = request.sid
	logging.info(f"[flask_sid={flask_sid}] Received disconnect event from client terminal, closing SSH session and socket connection...")

	close_connection(flask_sid, socketio)


def handle_timeout(socketio: SocketIO):
	"""
	Handles the `timeout` event from the client terminal.

	EVENT: `timeout`
	"""
	flask_sid = request.sid
	logging.info(f"[flask_sid={flask_sid}] Received timeout event from client terminal, closing SSH session and socket connection...")

	socketio.emit(
		"ssh-output",
		{"output": f"{RED}Timed-out, this session was unused for too long. {RESET}", "timeout": True},
		namespace="/ssh",
		to=flask_sid
	)
	close_connection(flask_sid, socketio)


def handle_resize(data):
	"""
	Handles the resizing of the client terminal by adapting the dimensions of the ssh terminal.

	EVENT: `resize`
	:param data: Has `cols` and `rows`
	"""
	flask_sid = request.sid
	ssh_session = SSH_SESSION_STORE.get_session(flask_sid)

	if ssh_session is not None:
		ssh_channel = ssh_session.channel
		if ssh_channel is not None:
			logging.debug(f"[flask_sid={flask_sid}] Resizing terminal window to cols={data['cols']}, rows={data['rows']}")
			ssh_channel.resize_pty(width=data["cols"], height=data["rows"])



def close_connection(flask_sid, socketio: SocketIO, message: str = "The session was closed"):
	"""
	Disconnects the client terminal and closes the SSH session.
	"""
	session = SSH_SESSION_STORE.remove_and_close_session(flask_sid)

	if session is not None:
		logging.info(f"[flask_sid={flask_sid}] Removed SSH session from session store")

		session.client.close()
		session.channel.close()

		logging.info(f"[flask_sid={flask_sid}] SSH session closed")

		# Notify the client terminal to close the connection
		socketio.emit("ssh-output", {"output": f"{RED}{message}{RESET}"}, namespace="/ssh", to=flask_sid)
		socketio.emit("disconnect", namespace="/ssh", to=flask_sid)
		disconnect()
		logging.info(f"[flask_sid={flask_sid}] Socket connection closed")
	else:
		logging.warning(f"[flask_sid={flask_sid}] Could not close the SSH connection because it was not found in the session store (it could have been already closed)")

