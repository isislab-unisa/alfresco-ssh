import argparse
import io
import os
import paramiko
import logging
import sys

from routes import routes_blueprint
from utils import color_hostname_in_output, GREEN, RED, RESET, decrypt_credentials, cypher
from stores import CREDENTIAL_STORE, SSH_SESSION_STORE
from flask import Flask, request
from flask_socketio import SocketIO, disconnect

logging.getLogger("werkzeug").setLevel(logging.ERROR)

__version__ = "1.0.0"

# The main Flask app
app = Flask(
	__name__,
	template_folder=".",
	static_folder=".",
	static_url_path="",
)

# Security
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", os.urandom(24))


# Socket.IO
socketio = SocketIO(app, async_mode="eventlet")  # TODO: Search for another async mode


def close_connection(sid):
	"""
	Handles the disconnection of the client terminal and closes the ssh session
	"""
	session = SSH_SESSION_STORE.pop(sid, None)

	if session:
		session["channel"].close()
		session["client"].close()

		logging.info(f"ssh session closed for {sid}")

		# Notify the client terminal to close the connection
		socketio.emit("ssh-output", {"output": f"{RED} The session was terminated{RESET}"}, namespace="/ssh", to=sid)
		socketio.emit("disconnect", namespace="/ssh", to=sid)
	else:
		logging.warning(f"could not close the connection {sid}, as no ssh session was found (or it was already closed)")


def read_and_emit_ssh_output(sid):
	"""
	Continuously reads the output of ssh and sends it to the client terminal

	EVENT: `ssh-output`
	:param sid: The session id of the source client terminal
	"""
	max_read_bytes = 1024 * 20
	ssh_channel = SSH_SESSION_STORE[sid]["channel"]

	while True:
		socketio.sleep(0.01)

		if ssh_channel and ssh_channel.recv_ready():
			output = ssh_channel.recv(max_read_bytes).decode(errors="ignore")

			logging.debug(f"output for {sid}: {output}")

			# Use the input line buffer here
			# buffer = ssh_sessions.get(sid, {}).get("input_line_buffer")

			colored_output = color_hostname_in_output(output)
			socketio.emit("ssh-output", {"output": colored_output}, namespace="/ssh", to=sid)


@socketio.on("ssh-input", namespace="/ssh")
def ssh_input(data):
	"""
	Reads the input (one character) from the client terminal and sends it to the ssh terminal

	EVENT: `ssh-input`
	:param data: Has `input`
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
			close_connection(sid)


@socketio.on("resize", namespace="/ssh")
def resize(data):
	"""
	Handles the resizing of the client terminal by adapting the dimensions of the ssh terminal

	EVENT: `resize`
	:param data: Has `cols` and `rows`
	"""
	sid = request.sid
	ssh_channel = SSH_SESSION_STORE.get(sid, {}).get("channel")

	if ssh_channel:
		logging.debug(f"resizing terminal {sid} window to {data['rows']}x{data['cols']}")
		ssh_channel.resize_pty(width=data["cols"], height=data["rows"])


@socketio.on("start-session", namespace="/ssh")
def start_session(data):
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

		# According to https://github.com/cs01/pyxtermjs:
		# Logging/print statements must go after this
		# If they come before, the background task never starts
		socketio.start_background_task(target=read_and_emit_ssh_output, sid=sid)

		if "password" in credentials:
			logging.info(f"ssh session established for {sid} with password")
		else:
			logging.info(f"ssh session established for {sid} with key")
	except Exception as e:
		logging.error(f"ssh connection failed for {sid}: {e}")
		socketio.emit("ssh-output", {"output": f"{RED}{e}{RESET}"}, namespace="/ssh", to=sid)
		disconnect()


@socketio.on("disconnect", namespace="/ssh")
def disconnect_handler():
	"""
	Handles the `disconnect` event from the client terminal

	EVENT: `disconnect`
	"""
	sid = request.sid
	close_connection(sid)


def main():
	"""
	Main function, parses arguments and starts the server
	"""

	################################
	#         SETUP PARSER         #
	################################

	parser = argparse.ArgumentParser(
		description="A fully functional ssh terminal in your browser.",
		formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	)

	parser.add_argument("--port", default=5000,
						help="The port where the server runs (default is 5000)", type=int)
	parser.add_argument("--host", default="127.0.0.1",
						help="The host where the server runs (use 0.0.0.0 to allow access from local network)")
	parser.add_argument("--debug", action="store_true",
						help="Debug the server")
	parser.add_argument("--version", action="store_true",
						help="Prints the version of the program and exits")

	args = parser.parse_args()

	if args.version:
		print(__version__)
		exit(0)

	################################
	#         SETUP LOGGER         #
	################################

	log_format = f"{GREEN}alfresco-ssh > {RESET}%(levelname)s (%(funcName)s:%(lineno)s) %(message)s"

	logging.basicConfig(
		format=log_format,
		stream=sys.stdout,
		level=logging.DEBUG if args.debug else logging.INFO,
	)

	logging.info(f"serving on http://{args.host}:{args.port}")

	################################
	#    START SOCKET.IO SERVER    #
	################################

	app.register_blueprint(routes_blueprint)

	socketio.run(
		app,
		host=args.host,
		port=args.port,
		debug=args.debug,
	)


if __name__ == "__main__":
	main()
