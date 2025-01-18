import logging
import uuid
from datetime import datetime

from eventlet.green.http import HTTPStatus
from flask import request, jsonify, render_template, Blueprint
from werkzeug.datastructures import FileStorage

from utils import encrypt_credentials, sanitize_input, create_json_response
from stores import CREDENTIAL_STORE, Credentials

routes_blueprint = Blueprint('routes', __name__)

def get_credentials_from_request(source: dict, form_files_source: dict = None) -> Credentials:
	hostname: str | None = source.get("hostname", None)
	username: str | None = source.get("username", None)
	port: int = int(source.get("port", 22))
	ssh_key: str | None = None
	password: str | None = None

	if form_files_source is not None:
		ssh_key_file: FileStorage | None = form_files_source.get("ssh_key", None)

		if ssh_key_file is None:
			logging.warning("SSH key file missing in the request")
			raise ValueError("No SSH key file provided")
		else:
			ssh_key = ssh_key_file.read().decode("utf-8")
	else:
		password = source.get("password", None)

	return Credentials(
		hostname=hostname,
		port=port,
		username=username,
		ssh_key=ssh_key,
		password=password,
	)


@routes_blueprint.route("/create-credentials", methods=["POST"])
def create_credentials():
	"""Receives SSH credentials via POST request and returns a UUID."""
	credentials_uuid: str | None = None
	logging.info("Received a POST request for credentials creation")

	try:
		content_type = request.content_type
		logging.debug(f"Request content type: {content_type}")

		if content_type.startswith("multipart/form-data"): # TODO: Maybe instead of a file, receive a string
			logging.info("Processing SSH key authentication")
			new_credentials = get_credentials_from_request(request.form, request.files)
			CREDENTIAL_STORE.add_credentials(new_credentials)
		elif content_type == "application/json":
			logging.info("Processing password authentication")
			data = sanitize_input(request.json)
			new_credentials = get_credentials_from_request(data)
			CREDENTIAL_STORE.add_credentials(new_credentials)
		else:
			return create_json_response(
				error=True,
				error_message="Unsupported content type",
				status_code=HTTPStatus.UNSUPPORTED_MEDIA_TYPE
			)
	except KeyError as e:
		logging.warning(f"Error for {credentials_uuid}: {e}")
		return create_json_response(
			error=True,
			error_message="Missing fields",
			status_code=HTTPStatus.BAD_REQUEST
		)
	except ValueError as e:
		logging.warning(f"Error for {credentials_uuid}: {e}")
		return create_json_response(
			error=True,
			error_message=str(e),
			status_code=HTTPStatus.BAD_REQUEST
		)
	except Exception as e:
		logging.error(f"Internal Server Error for {credentials_uuid}: {e}")
		return create_json_response(
			error=True,
			error_message="Internal server error",
			status_code=HTTPStatus.INTERNAL_SERVER_ERROR
		)

	logging.debug(f"Credentials for {credentials_uuid} encrypted and stored")

	return create_json_response(
		json={"credentials_uuid": credentials_uuid},
		status_code=HTTPStatus.OK
	)


@routes_blueprint.route("/<credentials_uuid>")
def terminal(credentials_uuid):
	credentials = CREDENTIAL_STORE.get_credentials(credentials_uuid)

	if credentials is None:
		logging.warning(f"Could not find credentials for {credentials_uuid}")
		return create_json_response(
			error=True,
			error_message=f"Could not find credentials for {credentials_uuid}",
			status_code=HTTPStatus.NOT_FOUND
		)

	logging.info(f"Requested a terminal with {credentials_uuid}")
	return render_template("index.html", credentials_uuid=credentials_uuid)

