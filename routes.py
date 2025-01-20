import logging
import uuid

from eventlet.green.http import HTTPStatus
from flask import request, render_template, Blueprint
from werkzeug.datastructures import FileStorage

from utils import sanitize_json_input, create_json_response
from stores import CREDENTIAL_STORE
from models.credentials import Credentials

routes_blueprint = Blueprint('routes', __name__)

def get_credentials_from_request(credentials_uuid: str, source: dict, files_source: dict = None) -> Credentials:
	"""
	Creates a Credentials object from a certain dict source.
	If the files_source is defined, it's a credential with SSH Key. Otherwise, it is with a password.
	:param credentials_uuid: UUID of the credentials.
	:param source: The source.
	:param files_source: The source of the form data (optional).
	:raises ValueError
	"""
	hostname: str | None = source.get("hostname", None)
	username: str | None = source.get("username", None)
	port: int = int(source.get("port", 22))

	ssh_key: str | None = None
	password: str | None = None

	if files_source is not None:
		ssh_key_file: FileStorage | None = files_source.get("ssh_key", None)

		if ssh_key_file is None:
			logging.warning("SSH key file missing in the request")
			raise ValueError("No SSH key file provided")
		else:
			ssh_key = ssh_key_file.read().decode("utf-8")
	else:
		password = source.get("password", None)

	return Credentials(
		credentials_uuid=credentials_uuid,
		hostname=hostname,
		port=port,
		username=username,
		ssh_key=ssh_key,
		password=password,
	)


@routes_blueprint.route("/create-credentials", methods=["POST"])
def create_credentials():
	"""Receives SSH credentials via POST request and returns a UUID."""
	credentials_uuid = str(uuid.uuid4())
	logging.info(f"[credentials_uuid={credentials_uuid}] Received a POST request for credentials creation")

	try:
		content_type = request.content_type
		logging.debug(f"[credentials_uuid={credentials_uuid}] Request content type: {content_type}")

		if content_type.startswith("multipart/form-data"): # TODO: Maybe instead of a file, receive a string
			logging.info(f"[credentials_uuid={credentials_uuid}] Processing SSH key authentication")
			new_credentials = get_credentials_from_request(credentials_uuid, request.form, request.files)
			CREDENTIAL_STORE.add_credentials(new_credentials)
		elif content_type == "application/json":
			logging.info(f"[credentials_uuid={credentials_uuid}] Processing password authentication")

			try:
				req_json = request.json
			except Exception as e:
				# Bad JSON
				logging.warning(f"[credentials_uuid={credentials_uuid}] Error: {e}")
				return create_json_response(
					error=True,
					error_message=str(e),
					status_code=HTTPStatus.BAD_REQUEST
				)

			data = sanitize_json_input(req_json)
			new_credentials = get_credentials_from_request(credentials_uuid, data)
			CREDENTIAL_STORE.add_credentials(new_credentials)
		else:
			return create_json_response(
				error=True,
				error_message="Unsupported content type",
				status_code=HTTPStatus.UNSUPPORTED_MEDIA_TYPE
			)
	except KeyError as e:
		logging.warning(f"[{credentials_uuid}] Error: {e}")
		return create_json_response(
			error=True,
			error_message="Missing fields",
			status_code=HTTPStatus.BAD_REQUEST
		)
	except ValueError as e:
		logging.warning(f"[credentials_uuid={credentials_uuid}] Error: {e}")
		return create_json_response(
			error=True,
			error_message=str(e),
			status_code=HTTPStatus.BAD_REQUEST
		)
	except Exception as e:
		logging.error(f"[credentials_uuid={credentials_uuid}] Internal Server Error: {type(e)}")
		return create_json_response(
			error=True,
			error_message="Internal server error",
			status_code=HTTPStatus.INTERNAL_SERVER_ERROR
		)

	logging.info(f"[credentials_uuid={credentials_uuid}] Credentials created and stored")

	return create_json_response(
		json={"credentials_uuid": credentials_uuid},
		status_code=HTTPStatus.OK
	)


@routes_blueprint.route("/")
def terminal():
	credentials_uuid = request.args.get("connect") # Query param
	credentials = CREDENTIAL_STORE.get_credentials(credentials_uuid)

	if credentials is None:
		logging.warning(f"[credentials_uuid={credentials_uuid}] Could not find stored credentials")
		return create_json_response(
			error=True,
			error_message=f"Could not find stored credentials with ID {credentials_uuid}",
			status_code=HTTPStatus.NOT_FOUND
		)

	logging.info(f"[credentials_uuid={credentials_uuid}] Requested a terminal, switching to flask_sid for log identification")
	return render_template("index.html", credentials_uuid=credentials_uuid)

