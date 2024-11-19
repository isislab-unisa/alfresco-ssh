import argparse
import os
import logging
import sys

from message_handlers import register_message_handlers
from routes import routes_blueprint
from utils import GREEN, RESET
from flask import Flask
from flask_socketio import SocketIO

logging.getLogger("werkzeug").setLevel(logging.ERROR)

__version__ = "1.0.0"

app = Flask(
	__name__,
	template_folder=".",
	static_folder=".",
	static_url_path="",
)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
socketio = SocketIO(app, async_mode="eventlet")  # TODO: Search for another async mode

# Register functions
app.register_blueprint(routes_blueprint)
register_message_handlers(socketio)

def main():
	################################
	#         SETUP PARSER         #
	################################

	parser = argparse.ArgumentParser(
		description="A fully functional ssh terminal in your browser.",
		formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	)

	parser.add_argument("--port", default=5000,
						help="The port where the server runs (default is 5000)", type=int)
	parser.add_argument("--host", default="127.0.0.1",
						help="The host where the server runs (use 0.0.0.0 to allow access from local network)")
	parser.add_argument("--debug", action="store_true",
						help="Debug the server")
	parser.add_argument("--version", action="store_true",
						help="Prints the version of the program and exits")

	args = parser.parse_args()

	if args.version:
		print(__version__)
		exit(0)

	################################
	#         SETUP LOGGER         #
	################################

	log_format = f"{GREEN}alfresco-ssh > {RESET}%(levelname)s (%(funcName)s:%(lineno)s) %(message)s"

	logging.basicConfig(
		format=log_format,
		stream=sys.stdout,
		level=logging.DEBUG if args.debug else logging.INFO,
	)

	logging.info(f"serving on http://{args.host}:{args.port}")

	################################
	#    START SOCKET.IO SERVER    #
	################################

	socketio.run(
		app,
		host=args.host,
		port=args.port,
		debug=args.debug,
	)


if __name__ == "__main__":
	main()