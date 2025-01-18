import uuid
from datetime import datetime

from utils import encrypt, decrypt


class Credentials:
	def __init__(self,
				 hostname: str, username: str, port: int = 22,
				 ssh_key: str = None, password: str = None):
		"""
		An object representing the credentials for an SSH connection. Either an ssh key or password must be submitted.
		:param hostname: The hostname of the SSH connection.
		:param username: The username of the SSH connection.
		:param port: The port of the SSH connection.
		:param ssh_key: The ssh key of the SSH connection.
		:param password: The password of the SSH connection.
		"""
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

		self.authentication_type = None
		self.ssh_key = None
		self.password = None

		if ssh_key is not None:
			self.ssh_key = encrypt(ssh_key)
			self.authentication_type = "ssh_key"
		else:
			self.password = encrypt(password)
			self.authentication_type = "password"

		self.creation_time = datetime.now()

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

	def add_credentials(self, credentials: Credentials) -> Credentials:
		"""
		Adds a new credentials object in the store.
		:param credentials: The credentials to add.
		:raises ValueError
		"""
		credentials_uuid = credentials.uuid

		if credentials_uuid in self.store:
			raise ValueError(f"Could not add credentials with {credentials_uuid} because it already exists.")

		self.store[credentials_uuid] = credentials
		return self.store[credentials_uuid]

	def get_credentials(self, credentials_uuid: str) -> Credentials | None:
		"""Returns the credentials object for the given credentials uuid. If not found, returns None."""
		return self.store.get(credentials_uuid, None)

	def remove_credentials(self, credentials_uuid: str) -> Credentials | None:
		"""Removes the credentials object for the given credentials uuid."""
		return self.store.pop(credentials_uuid, None)

	def list_credentials(self):
		"""Returns a list of all credentials' keys."""
		return list(self.store.keys())
