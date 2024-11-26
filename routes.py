import logging
import uuid
from datetime import datetime

from flask import request, jsonify, render_template, Blueprint
from utils import encrypt_credentials, sanitize_input
from stores import CREDENTIAL_STORE

routes_blueprint = Blueprint('routes', __name__)

@routes_blueprint.route("/create-session", methods=["POST"])
def create_session():
	"""Receives SSH credentials via POST request and returns a UUID."""
	create_session_id = None
	try:
		if request.content_type.startswith("multipart/form-data"):
			# SSH Key authentication
			hostname = request.form["hostname"]
			port = int(request.form.get("port", 22))
			username = request.form["username"]

			if "ssh_key" not in request.files:
				raise ValueError("No SSH key file provided")

			ssh_key_file = request.files["ssh_key"]  # TODO: Maybe instead of a file, receive a string
			ssh_key_content: str = ssh_key_file.read().decode("utf-8")

			# Generate a unique session ID (UUID)
			create_session_id = str(uuid.uuid4())
			logging.info(f"generated a new create_session_id: {create_session_id}")

			credentials = {
				"hostname": hostname,
				"port": port,
				"username": username,
				"ssh_key": ssh_key_content,
				"creation_time": datetime.now()
			}
			CREDENTIAL_STORE[create_session_id] = encrypt_credentials(credentials)
			logging.debug(f"credentials for {create_session_id} encrypted and stored")

		elif request.content_type == "application/json":
			# Password authentication
			data = sanitize_input(request.json)
			hostname = data["hostname"]
			port = int(data.get("port", 22))
			username = data["username"]
			password = data["password"]

			# Generate a unique session ID (UUID)
			create_session_id = str(uuid.uuid4())
			logging.info(f"generated a new create_session_id: {create_session_id}")

			credentials = {
				"hostname": hostname,
				"port": port,
				"username": username,
				"password": password,
				"creation_time": datetime.now()
			}
			CREDENTIAL_STORE[create_session_id] = encrypt_credentials(credentials)
			logging.debug(f"credentials for {create_session_id} encrypted and stored")

		else:
			return jsonify({"error": "Unsupported content type"}), 400

		url = f"{request.scheme}://{request.host}/{create_session_id}"
		logging.debug(url)

		return jsonify({
			"create_session_id": create_session_id,
			"url": url
		}), 200


	except KeyError as e:
		logging.error(f"Error for {create_session_id}: {e}")
		return jsonify({"error": "Missing field"}), 400
	except ValueError as e:
		logging.error(f"Error for {create_session_id}: {e}")
		return jsonify({"error": str(e)}), 400
	except Exception as e:
		logging.error(f"Error for {create_session_id}: {e}")
		return jsonify({"error": "Internal server error"}), 500


@routes_blueprint.route("/<create_session_id>")
def terminal(create_session_id):
	if create_session_id not in CREDENTIAL_STORE:
		return "Session not found", 404

	logging.info(f"requested a terminal with {create_session_id}")
	return render_template("index.html", create_session_id=create_session_id)
