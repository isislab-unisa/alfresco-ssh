import argparse
import io
import os
import uuid
import paramiko
import logging
import sys

from utils import color_hostname_in_output, GREEN, RED, RESET, sanitize_input, encrypt_credentials, decrypt_credentials
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, disconnect
from cryptography.fernet import Fernet

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
CREDENTIALS_KEY = os.getenv("CREDENTIALS_KEY", Fernet.generate_key())
cypher = Fernet(CREDENTIALS_KEY)

# Dictionary to keep the SSH session for each connected user
# TODO: Find a way to limit the number of sessions
ssh_sessions = {}

# Dictionary to keep the SSH credentials for each created session
# TODO: Find a way to delete credentials for unused url
credentials_store = {}

# Socket.IO
socketio = SocketIO(app, async_mode="eventlet")  # TODO: Search for another async mode


def close_connection(sid):
	"""
	Handles the disconnection of the client terminal and closes the ssh session
	"""
	session = ssh_sessions.pop(sid, None)

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
	ssh_channel = ssh_sessions[sid]["channel"]

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
	ssh_channel = ssh_sessions.get(sid, {}).get("channel")

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
	ssh_channel = ssh_sessions.get(sid, {}).get("channel")

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

	if create_session_id not in credentials_store:
		logging.error(f"Invalid create connection ID: {create_session_id}")
		disconnect()

	logging.info(f"new client connected (created with {create_session_id}): {sid}")

	try:
		encrypted_credentials = credentials_store.pop(create_session_id, None)

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

		ssh_sessions[sid] = {
			"client": ssh_client,
			"channel": ssh_channel,
			# "input_line_buffer": []
		}

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


@app.route("/<create_session_id>")
def terminal(create_session_id):
	if create_session_id not in credentials_store:
		return "Session not found", 404

	logging.info(f"requested a terminal with {create_session_id}")
	return render_template("index.html", create_session_id=create_session_id)


@app.route("/create-session", methods=["POST"])
def create_session():
	"""Receives SSH credentials via POST request and returns a UUID."""

	try:
		if request.content_type.startswith("multipart/form-data"):
			# SSH Key authentication
			hostname = request.form["hostname"]
			port = int(request.form.get("port", 22))
			username = request.form["username"]

			if "ssh_key" not in request.files:
				return jsonify({"error": "No SSH key file provided"}), 400

			ssh_key_file = request.files["ssh_key"]
			ssh_key_content = ssh_key_file.read().decode("utf-8")

			# Generate a unique session ID (UUID)
			create_session_id = str(uuid.uuid4())
			logging.info(f"generated a new create_session_id: {create_session_id}")

			credentials = {
				"hostname": hostname,
				"port": port,
				"username": username,
				"ssh_key": ssh_key_content,
			}
			credentials_store[create_session_id] = encrypt_credentials(credentials, cypher)
			logging.debug(f"credentials for {create_session_id} encrypted")

		elif request.content_type == "application/json":
			# Password authentication
			data = sanitize_input(request.json)
			hostname = data["hostname"]
			port = int(data.get("port", 22))
			username = data["username"]
			password = data["password"]

			# Generate a unique session ID (UUID)
			create_session_id = str(uuid.uuid4())
			logging.info(f"generated a new create_session_id: {create_session_id}")

			credentials = {
				"hostname": hostname,
				"port": port,
				"username": username,
				"password": password,
			}
			credentials_store[create_session_id] = encrypt_credentials(credentials, cypher)
			logging.debug(f"credentials for {create_session_id} encrypted")

		else:
			return jsonify({"error": "Unsupported content type"}), 400

		url = f"{request.scheme}://{request.host}/{create_session_id}"
		logging.debug(url)

		return jsonify({
			"create_session_id": create_session_id,
			"url": url
		}), 200


	except KeyError as e:
		logging.debug(e)
		return jsonify({"error": "Missing field"}), 400
	except ValueError as e:
		logging.debug(e)
		return jsonify({"error": str(e)}), 400
	except Exception as e:
		logging.debug(e)
		return jsonify({"error": ""}), 500


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

	parser.add_argument("-p", "--port", default=5000, help="Port to run server on", type=int)
	parser.add_argument("--host", default="127.0.0.1",
						help="Host to run server on (use 0.0.0.0 to allow access from other hosts)", )
	parser.add_argument("--debug", action="store_true", help="Debug the server")
	parser.add_argument("--version", action="store_true", help="Print version and exit")

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

	socketio.run(
		app,
		host=args.host,
		port=args.port,
		debug=args.debug,
	)


if __name__ == "__main__":
	main()
