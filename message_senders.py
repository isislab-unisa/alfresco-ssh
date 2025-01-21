import logging

from flask_socketio import SocketIO

from utils import close_connection
from stores import SSH_SESSION_STORE


def send_ssh_output(flask_sid, socketio: SocketIO):
	"""
    Continuously reads the output of ssh and sends it to the client terminal.

	Sends the `ssh-output` event to the client.
    """
	max_read_bytes = 1024 * 20
	ssh_session = SSH_SESSION_STORE.get_session(flask_sid)

	if not ssh_session or not ssh_session.channel:
		logging.warning(f"[flask_sid={flask_sid}] SSH session or channel not found. Terminating background task.")
		return

	ssh_channel = ssh_session.channel

	try:
		while ssh_channel and not ssh_channel.closed:
			socketio.sleep(0.01)

			if ssh_channel.recv_ready():
				try:
					output = ssh_channel.recv(max_read_bytes).decode(errors="ignore")
					logging.debug(f"[flask_sid={flask_sid}] Received output from SSH server: {output}")

					# Use the input line buffer here
					#buffer = SSH_SESSION_STORE.get_session(flask_sid).input_line_buffer

					# Use colored hostname
					#colored_output = color_hostname_in_output(output)
					#output = colored_output

					# Emit the output to the client
					socketio.emit("ssh-output", {"output": output}, namespace="/ssh", to=flask_sid)
				except Exception as e:
					logging.error(f"[flask_sid={flask_sid}] Error while reading from SSH channel: {e}")
					break

	except Exception as e:
		logging.error(f"[flask_sid={flask_sid}] Unexpected error in SSH output loop: {e}")
		close_connection(flask_sid, socketio)
	finally:
		logging.info(f"[flask_sid={flask_sid}] Terminating SSH output loop.")
