from paramiko import SSHClient, Channel

from .credentials import Credentials


class SSHSession:
	def __init__(self, flask_request_sid, client: SSHClient, channel: Channel, credentials: Credentials):
		"""
		An object representing the active SSH session.
		:param flask_request_sid: The session id of the flask request.
		:param client: The active SSH client.
		:param channel: The active SSH channel.
		:param credentials: The credentials object.
		"""
		self.flask_request_sid = flask_request_sid

		self.client = client
		self.channel = channel
		self.credentials = credentials

		#self.input_line_buffer = []


class SSHSessionStore:
	def __init__(self):
		self.store = {}

	def add_session(self, session: SSHSession):
		"""
		Adds a new SSH session object in the store.
		:param session: The session to add.
		:raises ValueError
		"""
		flask_sid = session.flask_request_sid

		if flask_sid in self.store:
			raise ValueError(f"Could not add ssh session with {flask_sid} because it already exists.")

		self.store[flask_sid] = session

	def get_session(self, flask_request_sid) -> SSHSession | None:
		"""Returns the active SSH session for the given flask session id. If not found, returns None."""
		return self.store.get(flask_request_sid, None)

	def remove_session(self, flask_request_sid) -> SSHSession | None:
		"""Deletes the active SSH session for the given flask session id."""
		return self.store.pop(flask_request_sid, None)

	def list_sessions(self):
		"""Lists the active SSH sessions' keys."""
		return list(self.store.keys())



