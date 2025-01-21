import logging

from paramiko import SSHClient, Channel
from threading import Lock


class SSHSession:
	def __init__(self, flask_request_sid, client: SSHClient, channel: Channel):
		"""
        Represents an active SSH session.

        :param flask_request_sid: The session ID of the Flask request.
        :param client: The active SSH client.
        :param channel: The active SSH channel.
        """
		self.flask_request_sid = flask_request_sid
		self.client = client
		self.channel = channel
		#self.input_line_buffer = []  # unused_utils.py
		logging.debug(f"[flask_sid={flask_request_sid}] SSHSession created")

	def close(self):
		"""
		Closes the SSH client and channel to release resources.
		"""
		if self.channel:
			self.channel.close()
			logging.debug(f"[flask_sid={self.flask_request_sid}] SSH Channel closed")
		if self.client:
			self.client.close()
			logging.debug(f"[flask_sid={self.flask_request_sid}] SSH Client closed")



class SSHSessionStore:
	def __init__(self):
		"""
		A thread-safe store for managing `SSHSession` objects.
		"""
		self.store = {}
		self.lock = Lock()

	def add_session(self, session: SSHSession) -> SSHSession:
		"""
        Adds a new SSH session object to the store.

        :param session: The session to add.
        :raises ValueError: If a session with the same Flask SID already exists.
        :return: The added SSH session object.
        """
		with self.lock:
			flask_sid = session.flask_request_sid

			if flask_sid in self.store:
				logging.warning(f"[flask_sid={flask_sid}] Attempt to add duplicate SSH session")
				raise ValueError(f"Flask SID {flask_sid} already exists in the store")

			self.store[flask_sid] = session
			logging.debug(f"[flask_sid={flask_sid}] SSH session added to the store")
			return self.store[flask_sid]

	def get_session(self, flask_request_sid) -> SSHSession | None:
		"""
        Retrieves the active SSH session for the given Flask session ID. Returns None if not found.

        :param flask_request_sid: The Flask session ID.
        :return: The corresponding SSHSession object or None.
        """
		with self.lock:
			session = self.store.get(flask_request_sid, None)
			if session:
				logging.debug(f"[flask_sid={flask_request_sid}] SSH session retrieved from the store")
			else:
				logging.warning(f"[flask_sid={flask_request_sid}] SSH session not found in the store")
			return session

	def remove_and_close_session(self, flask_request_sid) -> SSHSession | None:
		"""
        Deletes the active SSH session for the given Flask session ID and closes its resources.

        :param flask_request_sid: The Flask session ID.
        :return: The removed SSHSession object or None.
        """
		with self.lock:
			session = self.store.pop(flask_request_sid, None)
			if session:
				session.close()
				logging.info(f"[flask_sid={flask_request_sid}] SSH session removed from the store and its resources are closed")
			else:
				logging.warning(f"[flask_sid={flask_request_sid}] Attempted to remove non-existent SSH session from the store")
			return session

	def list_sessions(self):
		"""
        Lists the active SSH session IDs currently in the store.

        :return: A list of Flask session IDs.
        """
		with self.lock:
			return list(self.store.keys())