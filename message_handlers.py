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

	@socketio.on("resize", namespace="/ssh")
	def handle_resize_wrapper(data):
		handle_resize(data)


def handle_start_session(data, socketio: SocketIO):
	"""
	Handles the connection of a new client terminal.

	EVENT: `connect`
	"""
	flask_sid = request.sid
	credentials_uuid = data['credentials_uuid']

	credentials = CREDENTIAL_STORE.get_credentials(credentials_uuid)

	if credentials is None:
		logging.error(f"No credentials found for {credentials_uuid}")
		disconnect()
		return


	logging.info(f"New client connected (created with {credentials_uuid}): {flask_sid}")

	try:
		CREDENTIAL_STORE.remove_credentials(credentials_uuid)

		logging.debug(f"Credentials with ID {credentials_uuid} removed")

		hostname = credentials.decrypt_hostname()
		port = credentials.decrypt_port()
		username = credentials.decrypt_username()

		# Create the SSH client and connect to remote SSH server
		ssh_client = paramiko.SSHClient()
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		if credentials.authentication_type == "password":
			# Connect with password
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
			logging.info(f"SSH session established for {flask_sid} with password")
		else:
			logging.info(f"SSH session established for {flask_sid} with key")
	except Exception as e:
		logging.error(f"SSH connection failed for {flask_sid}: {e}")
		socketio.emit("ssh-output", {"output": f"{RED}{e}{RESET}"}, namespace="/ssh", to=flask_sid)
		close_connection(flask_sid, socketio)


def handle_ssh_input(data, socketio: SocketIO):
	"""
	Reads the input (one character) from the client terminal and sends it to the ssh terminal.

	EVENT: `ssh-input`
	"""
	flask_sid = request.sid
	ssh_session = SSH_SESSION_STORE.get_session(flask_sid)
	ssh_channel = ssh_session.channel

	if ssh_channel is not None and ssh_channel.send_ready():
		if len(data["input"]) == 1:
			logging.debug(f"Received input from client terminal {flask_sid}: {data['input']} ({ord(data['input'])})")

		# Put the character in the input line buffer
		#buffer: list[int] = ssh_session.input_line_buffer
		#ssh_session.input_line_buffer = add_char_to_input_line_buffer(buffer, ord(data["input"]))
		#logging.debug(f"input buffer for {flask_sid}: {ssh_session.input_line_buffer}")

		else:
			logging.debug(f"Received input from client terminal {flask_sid}: {data['input']} (special key)")

		try:
			ssh_channel.send(data["input"])
			ssh_session.update_last_active()
		except OSError:
			logging.debug(f"Tried to send data to a closed socket for {flask_sid}")
			close_connection(flask_sid, socketio)

def handle_disconnect(socketio: SocketIO):
	"""
	Handles the `disconnect` event from the client terminal.

	EVENT: `disconnect`
	"""
	flask_sid = request.sid
	close_connection(flask_sid, socketio)


def handle_resize(data):
	"""
	Handles the resizing of the client terminal by adapting the dimensions of the ssh terminal.

	EVENT: `resize`
	:param data: Has `cols` and `rows`
	"""
	flask_sid = request.sid
	ssh_session = SSH_SESSION_STORE.get_session(flask_sid)
	ssh_channel = ssh_session.channel

	if ssh_channel is not None:
		logging.debug(f"Resizing terminal {flask_sid} window to cols={data['cols']}, rows={data['rows']}")
		ssh_channel.resize_pty(width=data["cols"], height=data["rows"])


def close_connection(flask_sid, socketio: SocketIO):
	"""
	Disconnects the client terminal and closes the SSH session.
	"""
	session = SSH_SESSION_STORE.remove_session(flask_sid)

	if session is not None:
		session.client.close()
		session.channel.close()

		logging.info(f"SSH session closed for {flask_sid}")

		# Notify the client terminal to close the connection
		socketio.emit("ssh-output", {"output": f"{RED}The session was terminated{RESET}"}, namespace="/ssh", to=flask_sid)
		socketio.emit("disconnect", namespace="/ssh", to=flask_sid)
	else:
		logging.warning(f"Could not close the connection {flask_sid}, as no SSH session was found (or it was already closed)")
