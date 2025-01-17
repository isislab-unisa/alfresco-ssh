import logging
import uuid
from datetime import datetime

from flask import request, jsonify, render_template, Blueprint
from utils import encrypt_credentials, sanitize_input
from stores import CREDENTIAL_STORE, Credentials

routes_blueprint = Blueprint('routes', __name__)

@routes_blueprint.route("/create-credentials", methods=["POST"])
def create_session():
	"""Receives SSH credentials via POST request and returns a UUID."""
	ssh_session_id = None
	logging.info("Received a POST request for credentials creation")

	try:
		content_type = request.content_type
		logging.debug(f"Request content type: {content_type}")

		if content_type.startswith("multipart/form-data"):
			logging.info("Processing SSH key authentication")

			hostname = request.form["hostname"]
			port = int(request.form.get("port", 22))
			username = request.form["username"]

			if "ssh_key" not in request.files:
				logging.warning("SSH key file missing in the request")
				raise ValueError("No SSH key file provided")

			ssh_key_file = request.files["ssh_key"]  # TODO: Maybe instead of a file, receive a string
			ssh_key_content: str = ssh_key_file.read().decode("utf-8")

			# Generate a unique ID to use  (UUID)
			ssh_session_id = str(uuid.uuid4())
			logging.info(f"Generated new SSH session ID: {ssh_session_id}")

			credentials = Credentials(
				ssh_session_id,
				hostname,
				port,
				username,
				ssh_key=ssh_key_content,
			)
			CREDENTIAL_STORE.add_credentials(credentials)

			logging.debug(f"credentials for {ssh_session_id} encrypted and stored")

		elif request.content_type == "application/json":
			# Password authentication
			data = sanitize_input(request.json)
			hostname = data["hostname"]
			port = int(data.get("port", 22))
			username = data["username"]
			password = data["password"]

			# Generate a unique session ID (UUID)
			ssh_session_id = str(uuid.uuid4())
			logging.info(f"generated a new create_session_id: {ssh_session_id}")

			credentials = Credentials(
				ssh_session_id,
				hostname,
				port,
				username,
				password=password,
			)
			CREDENTIAL_STORE.add_credentials(credentials)

			logging.debug(f"credentials for {ssh_session_id} encrypted and stored")

		else:
			return jsonify({"error": "Unsupported content type"}), 400

		url = f"{request.scheme}://{request.host}/{ssh_session_id}"
		logging.debug(url)

		return jsonify({
			"create_session_id": ssh_session_id,
			"url": url
		}), 200


	except KeyError as e:
		logging.error(f"Error for {ssh_session_id}: {e}")
		return jsonify({"error": "Missing field"}), 400
	except ValueError as e:
		logging.error(f"Error for {ssh_session_id}: {e}")
		return jsonify({"error": str(e)}), 400
	except Exception as e:
		logging.error(f"Error for {ssh_session_id}: {e}")
		return jsonify({"error": "Internal server error"}), 500


@routes_blueprint.route("/<create_session_id>")
def terminal(create_session_id):
	try:
		CREDENTIAL_STORE.get_credentials(create_session_id)
	except KeyError as e:
		logging.error(f"Error for {create_session_id}: {e}")
		return str(e), 404

	logging.info(f"requested a terminal with {create_session_id}")
	return render_template("index.html", create_session_id=create_session_id)
