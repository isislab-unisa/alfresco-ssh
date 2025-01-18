import logging

from flask_socketio import SocketIO
from stores import SSH_SESSION_STORE


def send_ssh_output(flask_sid, socketio: SocketIO):
	"""
	Continuously reads the output of ssh and sends it to the client terminal

	EVENT: `ssh-output`
	"""
	max_read_bytes = 1024 * 20
	ssh_session = SSH_SESSION_STORE.get_session(flask_sid)
	ssh_channel = ssh_session.channel

	while True:
		socketio.sleep(0.01)

		if ssh_channel is not None and ssh_channel.recv_ready():
			output = ssh_channel.recv(max_read_bytes).decode(errors="ignore")

			logging.debug(f"[flask_sid={flask_sid}] Received an output from SSH server: {output}")

			# Use the input line buffer here
			#buffer = SSH_SESSION_STORE.get_session(flask_sid).input_line_buffer

			# Use colored hostname
			#colored_output = color_hostname_in_output(output)
			#output = colored_output
			socketio.emit("ssh-output", {"output": output}, namespace="/ssh", to=flask_sid)
