from models.credentials import CredentialStore
from models.ssh_session import SSHSessionStore

# Dictionary to keep the SSH credentials for each created session
CREDENTIAL_STORE = CredentialStore()

# Dictionary to keep the SSH session for each connected user
# TODO: Find a way to limit the number of sessions
SSH_SESSION_STORE = SSHSessionStore()
