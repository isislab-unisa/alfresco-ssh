import uuid
from datetime import datetime
from typing import Literal

from paramiko.channel import Channel
from paramiko.client import SSHClient

from utils import encrypt, decrypt


class Credentials:
	def __init__(self,
				 hostname: str, username: str, port: int = 22,
				 ssh_key: str = None, password: str = None):
		"""An object representing the credentials for an SSH connection."""
		if (ssh_key is not None and password is not None) or (ssh_key is None and password is None):
			raise ValueError("You must provide exactly one of ssh_key or password")

		if hostname is None:
			raise ValueError("You must provide a hostname")

		if username is None:
			raise ValueError("You must provide a username")

		self.uuid = str(uuid.uuid4())

		self.hostname = encrypt(hostname)
		self.port = encrypt(str(port))
		self.username = encrypt(username)
		self.ssh_key = encrypt(ssh_key) if ssh_key else None
		self.password = encrypt(password) if password else None

		self.creation_time = datetime.now()

	def get_authentication_method_type(self) -> Literal["ssh_key", "password"]:
		if self.ssh_key is None:
			return "password"
		else:
			return "ssh_key"

	def decrypt_hostname(self) -> str:
		return decrypt(self.hostname)

	def decrypt_port(self) -> str:
		return decrypt(self.port)

	def decrypt_username(self) -> str:
		return decrypt(self.username)

	def decrypt_ssh_key(self) -> str | None:
		if self.ssh_key is None:
			return None
		return decrypt(self.ssh_key)

	def decrypt_password(self) -> str | None:
		if self.password is None:
			return None
		return decrypt(self.password)


class CredentialStore:
	def __init__(self):
		self.store = {}

	def add_credentials(self, credentials: Credentials):
		uuid = credentials.uuid

		if uuid in self.store:
			raise ValueError(f"Could not add credentials with {uuid} because they already exists.")

		self.store[uuid] = credentials

	def get_credentials(self, credentials_uuid: str) -> Credentials | None:
		return self.store.get(credentials_uuid, None)

	def remove_credentials(self, credentials_uuid: str) -> Credentials | None:
		return self.store.pop(credentials_uuid, None)

	def list_credentials(self):
		return list(self.store.keys())


# Dictionary to keep the SSH credentials for each created session
CREDENTIAL_STORE = CredentialStore()


class SSHSession:
	def __init__(self, flask_request_sid, client: SSHClient, channel: Channel, credentials: Credentials):
		self.flask_request_sid = flask_request_sid

		self.client = client
		self.channel = channel
		self.credentials = credentials

		self.last_active = datetime.now()
		self.input_line_buffer = []

	def update_last_active(self):
		self.last_active = datetime.now()




class SSHSessionStore:
	def __init__(self):
		self.store = {}

	def add_session(self, session: SSHSession):
		flask_sid = session.flask_request_sid

		if flask_sid in self.store:
			raise ValueError(f"Could not add ssh session with {flask_sid} because it already exists.")

		self.store[flask_sid] = session

	def get_session(self, flask_request_sid):
		return self.store.get(flask_request_sid, None)

	def remove_session(self, flask_request_sid):
		return self.store.pop(flask_request_sid, None)

	def list_sessions(self):
		return list(self.store.keys())


# Dictionary to keep the SSH session for each connected user
# TODO: Find a way to limit the number of sessions
SSH_SESSION_STORE = SSHSessionStore()
