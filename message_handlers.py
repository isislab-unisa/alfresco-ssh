import io
import logging

import paramiko
from flask import request
from flask_socketio import SocketIO, disconnect

from message_senders import send_ssh_output
from stores import CREDENTIAL_STORE, SSH_SESSION_STORE
from utils import decrypt_credentials, cypher, RED, RESET


def register_message_handlers(socketio: SocketIO):
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


def close_connection(sid, socketio: SocketIO):
	"""
	Disconnects the  client terminal and closes the ssh session
	"""
	session = SSH_SESSION_STORE.pop(sid, None)

	if session:
		session["channel"].close()
		session["client"].close()

		logging.info(f"ssh session closed for {sid}")

		# Notify the client terminal to close the connection
		socketio.emit("ssh-output", {"output": f"{RED}The session was terminated{RESET}"}, namespace="/ssh", to=sid)
		socketio.emit("disconnect", namespace="/ssh", to=sid)
	else:
		logging.warning(f"could not close the connection {sid}, as no ssh session was found (or it was already closed)")


def handle_start_session(data, socketio: SocketIO):
	"""
	Handles the connection of a new client terminal

	EVENT: `connect`
	"""
	sid = request.sid
	create_session_id = data['create_session_id']

	if create_session_id not in CREDENTIAL_STORE:
		logging.error(f"Invalid create connection ID: {create_session_id}")
		disconnect()

	logging.info(f"new client connected (created with {create_session_id}): {sid}")

	try:
		encrypted_credentials = CREDENTIAL_STORE.pop(create_session_id, None)

		if not encrypted_credentials:
			raise Exception(f"No credentials found for {create_session_id}")

		logging.debug(f"credentials for {create_session_id} taken and removed")

		credentials = decrypt_credentials(encrypted_credentials, cypher)
		logging.debug(f"credentials for {sid} decrypted with {create_session_id}")

		hostname = credentials["hostname"]
		port = credentials["port"]
		username = credentials["username"]

		# Create the SSH client and connect to remote SSH server
		ssh_client = paramiko.SSHClient()
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		if "password" in credentials:
			# Connect with password
			ssh_client.connect(
				hostname=hostname,
				port=port,
				username=username,
				password=credentials["password"],
				look_for_keys=False,
				allow_agent=False,
			)
		elif "ssh_key" in credentials:
			# Connect with SSH Key
			ssh_key = paramiko.RSAKey.from_private_key(io.StringIO(credentials["ssh_key"]))
			ssh_client.connect(
				hostname=hostname,
				port=port,
				username=username,
				pkey=ssh_key,
				look_for_keys=False,
				allow_agent=False,
			)
		else:
			raise ValueError("No valid authentication method provided")

		# Open an interactive SSH session
		ssh_channel = ssh_client.invoke_shell()
		ssh_channel.settimeout(0.0)

		SSH_SESSION_STORE[sid] = {
			"client": ssh_client,
			"channel": ssh_channel,
			# "input_line_buffer": []
		}

		# According to https://github.com/cs01/pyxtermjs (it seems to be fixed):
		# Logging/print statements must go after this
		# If they come before, the background task never starts
		socketio.start_background_task(
			target=send_ssh_output,
			sid=sid,
			socketio=socketio
		)

		if "password" in credentials:
			logging.info(f"ssh session established for {sid} with password")
		else:
			logging.info(f"ssh session established for {sid} with key")
	except Exception as e:
		logging.error(f"ssh connection failed for {sid}: {e}")
		socketio.emit("ssh-output", {"output": f"{RED}{e}{RESET}"}, namespace="/ssh", to=sid)
		close_connection(sid, socketio)


def handle_ssh_input(data, socketio: SocketIO):
	"""
	Reads the input (one character) from the client terminal and sends it to the ssh terminal

	EVENT: `ssh-input`
	"""
	sid = request.sid
	ssh_channel = SSH_SESSION_STORE.get(sid, {}).get("channel")

	if ssh_channel and ssh_channel.send_ready():
		if len(data["input"]) == 1:
			logging.debug(f"received input from client terminal {sid}: {data["input"]} ({ord(data['input'])})")

		# Put the character in the input line buffer
		# buffer: list[int] = ssh_sessions.get(sid, {}).get("input_line_buffer")
		# ssh_sessions[sid]["input_line_buffer"] = add_char_to_input_line_buffer(buffer, ord(data["input"]))
		# logging.debug(f"input buffer for {sid}: {ssh_sessions[sid]["input_line_buffer"]}")

		else:
			logging.debug(f"received input from client terminal {sid}: {data["input"]} (special key)")

		try:
			ssh_channel.send(data["input"])
		except OSError:
			logging.debug(f"tried to send data to a closed socket for {sid}")
			close_connection(sid, socketio)


def handle_disconnect(socketio: SocketIO):
	"""
	Handles the `disconnect` event from the client terminal

	EVENT: `disconnect`
	"""
	sid = request.sid
	close_connection(sid, socketio)


def handle_resize(data):
	"""
	Handles the resizing of the client terminal by adapting the dimensions of the ssh terminal

	EVENT: `resize`
	:param data: Has `cols` and `rows`
	"""
	sid = request.sid
	ssh_channel = SSH_SESSION_STORE.get(sid, {}).get("channel")

	if ssh_channel:
		logging.debug(f"resizing terminal {sid} window to cols={data['cols']}, rows={data['rows']}")
		ssh_channel.resize_pty(width=data["cols"], height=data["rows"])
