import os
import uuid
import logging
from threading import Lock
from cryptography.fernet import Fernet


class Credentials:
	def __init__(self, credentials_uuid: str,
				 hostname: str, username: str, port: int = 22,
				 ssh_key: str = None, password: str = None):
		"""
		Represents the credentials for an SSH connection. Ensures either an SSH key or password is provided.

        :param credentials_uuid: Unique identifier for the credentials (must be a valid UUID).
        :param hostname: The hostname of the SSH connection (e.g., IP address or domain).
        :param username: The username for the SSH connection.
        :param port: The port number for the SSH connection (default is 22).
        :param ssh_key: The private SSH key for authentication (optional).
        :param password: The password for authentication (optional).
        :raises ValueError: If validation of inputs fails.
		"""
		if (ssh_key is not None and password is not None) or (ssh_key is None and password is None):
			raise ValueError("You must provide exactly one of ssh_key or password.")

		if hostname is None:
			raise ValueError("You must provide a hostname.")

		if username is None:
			raise ValueError("You must provide a username.")

		if not self.is_valid_uuid(credentials_uuid):
			raise ValueError("Invalid UUID provided for credentials_uuid.")

		self.uuid = credentials_uuid
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

		logging.debug(f"[credentials_uuid={credentials_uuid}] Credentials created")

	def decrypt_hostname(self) -> str:
		"""Decrypts and returns the hostname."""
		return decrypt(self.hostname)

	def decrypt_port(self) -> str:
		"""Decrypts and returns the port."""
		return decrypt(self.port)

	def decrypt_username(self) -> str:
		"""Decrypts and returns the username."""
		return decrypt(self.username)

	def decrypt_ssh_key(self) -> str | None:
		"""Decrypts and returns the SSH key if present, otherwise returns None."""
		if self.ssh_key is None:
			return None
		return decrypt(self.ssh_key)

	def decrypt_password(self) -> str | None:
		"""Decrypts and returns the password if present, otherwise returns None."""
		if self.password is None:
			return None
		return decrypt(self.password)

	@staticmethod
	def is_valid_uuid(uuid_to_test: str) -> bool:
		"""Validates whether a string is a valid UUID."""
		try:
			uuid.UUID(uuid_to_test)
			return True
		except ValueError:
			return False


class CredentialStore:
	def __init__(self):
		"""
		A thread-safe in-memory store for managing `Credentials` objects.
		"""
		self.store = {}
		self.lock = Lock()

	def add_credentials(self, credentials: Credentials) -> Credentials:
		"""
        Adds a new credentials object to the store.

        :param credentials: The credentials to add.
        :raises ValueError: If credentials with the same UUID already exist.
        :return: The added credentials object.
        """
		with self.lock:
			credentials_uuid = credentials.uuid

			if credentials_uuid in self.store:
				logging.warning(f"[credentials_uuid={credentials_uuid}] Attempt to add duplicate credentials")
				raise ValueError(f"UUID {credentials_uuid} already exists in the store")

			self.store[credentials_uuid] = credentials
			logging.debug(f"[credentials_uuid={credentials_uuid}] Credentials added to the store")
			return self.store[credentials_uuid]

	def get_credentials(self, credentials_uuid: str) -> Credentials | None:
		"""
        Retrieves the credentials object for the given UUID. Returns None if not found.

        :param credentials_uuid: The UUID of the credentials to retrieve.
        :return: The corresponding credentials object or None.
        """
		with self.lock:
			result = self.store.get(credentials_uuid, None)
			if result:
				logging.debug(f"[credentials_uuid={credentials_uuid}] Credentials retrieved from the store")
			else:
				logging.warning(f"[credentials_uuid={credentials_uuid}] Credentials not found in the store")
			return result

	def remove_credentials(self, credentials_uuid: str) -> Credentials | None:
		"""
        Removes the credentials object for the given UUID if it exists.

        :param credentials_uuid: The UUID of the credentials to remove.
        :return: The removed credentials object or None.
        """
		with self.lock:
			result = self.store.pop(credentials_uuid, None)
			if result:
				logging.debug(f"[credentials_uuid={credentials_uuid}] Credentials removed from the store")
			else:
				logging.warning(f"[credentials_uuid={credentials_uuid}] Attempted to remove non-existent credentials from the store")
			return result

	def list_credentials(self):
		"""
        Returns a list of all credentials' UUIDs currently in the store.
        """
		with self.lock:
			keys = list(self.store.keys())
			logging.debug(f"Listing all credentials UUIDs: {keys}")
			return keys


CREDENTIALS_KEY = os.getenv("CREDENTIALS_KEY", Fernet.generate_key())
cipher = Fernet(CREDENTIALS_KEY)


def encrypt(data: str, encoding: str = "utf-8") -> bytes:
	"""
    Encrypts the given string using the provided encoding.

    :param data: The string to encrypt.
    :param encoding: The character encoding to use (default is UTF-8).
    :return: The encrypted data as bytes.
    """
	encrypted_data = cipher.encrypt(data.encode(encoding))
	return encrypted_data


def decrypt(data: bytes, encoding: str = "utf-8") -> str:
	"""
    Decrypts the given encrypted bytes using the provided encoding.

    :param data: The encrypted data as bytes.
    :param encoding: The character encoding to use (default is UTF-8).
    :return: The decrypted string.
    """
	decrypted_data = cipher.decrypt(data).decode(encoding)
	return decrypted_data

