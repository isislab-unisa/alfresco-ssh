import logging

from flask_socketio import SocketIO

from stores import SSH_SESSION_STORE
from utils import color_hostname_in_output


def send_ssh_output(sid, socketio: SocketIO):
	"""
	Continuously reads the output of ssh and sends it to the client terminal

	EVENT: `ssh-output`
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
