from datetime import datetime
from utils import encrypt, decrypt


class Credentials:
	def __init__(self, create_session_id: str,
				 hostname: str, port: int, username: str,
				 ssh_key: str = None, password: str = None):
		"""An object representing the credentials for an SSH connection."""
		if (ssh_key is not None and password is not None) or (ssh_key is None and password is None):
			raise ValueError("You must provide exactly one of ssh_key or password")

		self.create_session_id = create_session_id
		self.creation_time = datetime.now()

		self.hostname = encrypt(hostname)
		self.port = encrypt(str(port))
		self.username = encrypt(username)

		self.ssh_key = encrypt(ssh_key) if ssh_key else None
		self.password = encrypt(password) if password else None

	def decrypt_hostname(self):
		return decrypt(self.hostname)

	def decrypt_port(self):
		return decrypt(self.port)

	def decrypt_username(self):
		return decrypt(self.username)

	def decrypt_ssh_key(self):
		if self.ssh_key is None:
			return None
		return decrypt(self.ssh_key)

	def decrypt_password(self):
		if self.password is None:
			return None
		return decrypt(self.password)


class CredentialStore:
	def __init__(self):
		self.credentials_store = {}

	def add_credentials(self, credentials: Credentials):
		if credentials.create_session_id in self.credentials_store:
			raise ValueError(f"Credentials with session ID {credentials.create_session_id} already exist.")

		self.credentials_store[credentials.create_session_id] = credentials

	def get_credentials(self, create_session_id: str) -> Credentials:
		credentials = self.credentials_store.get(create_session_id)

		if not credentials:
			raise KeyError(f"Credentials with session ID {create_session_id} not found.")

		return credentials

	def remove_credentials(self, create_session_id: str):
		if create_session_id in self.credentials_store:
			del self.credentials_store[create_session_id]
		else:
			raise KeyError(f"Credentials with session ID {create_session_id} not found.")

	def list_credentials(self):
		return list(self.credentials_store.keys())



# Dictionary to keep the SSH credentials for each created session
CREDENTIAL_STORE = CredentialStore()

# Dictionary to keep the SSH session for each connected user
# TODO: Find a way to limit the number of sessions
SSH_SESSION_STORE = {}
