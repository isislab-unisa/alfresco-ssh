import argparse
import logging
import socket
import sys
import signal
from flask import Flask
from flask_socketio import SocketIO

from message_handlers import register_message_handlers
from routes import routes_blueprint
from utils import GREEN, RESET


logging.getLogger("werkzeug").setLevel(logging.ERROR)
__version__ = "1.1.1"

app = Flask(
	__name__,
	template_folder=".",
	static_folder=".",
	static_url_path="",
)

socketio = SocketIO(
	app,
	async_mode="eventlet",  # eventlet, gevent or threading
)

# Register project functions
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
	parser.add_argument("--host", default="localhost",
						help="The host where the server runs, can be localhost or localnetwork (default is localhost)")
	parser.add_argument("--debug", action="store_true",
						help="Debug the server")
	parser.add_argument("--version", action="store_true",
						help="Prints the version of the program and exits")

	args = parser.parse_args()

	################################
	#         SETUP LOGGER         #
	################################

	log_format = f"{GREEN}alfresco-ssh > {RESET}%(levelname)s %(message)s"
	log_format_debug = f"{GREEN}alfresco-ssh > {RESET}%(levelname)s (%(funcName)s:%(lineno)s) %(message)s"

	logging.basicConfig(
		format=log_format_debug if args.debug else log_format,
		stream=sys.stdout,
		level=logging.DEBUG if args.debug else logging.INFO,
	)

	if args.version:
		logging.info(f"Version: {__version__}")
		sys.exit(0)

	if not (1 <= args.port <= 65535):
		logging.fatal("Invalid port number, it must be between 1 and 65535")
		sys.exit(1)

	if args.host == "localnetwork":
		local_network_ip = socket.gethostbyname(socket.gethostname())
		logging.info(f"serving on local network http://{local_network_ip}:{args.port}")
	elif args.host == "localhost":
		logging.info(f"serving on http://{args.host}:{args.port}")
	else:
		logging.fatal("Invalid host, it must be either localhost or localnetwork")
		sys.exit(1)

	################################
	#    START SOCKET.IO SERVER    #
	################################

	try:
		socketio.run(
			app,
			host=args.host,
			port=args.port,
			debug=args.debug,
		)
	except Exception as e:
		logging.fatal(f"Error while starting socketio: {e}")
		sys.exit(1)


def graceful_shutdown(sig, frame):
	"""
	:param sig: Needed by signal.
	:param frame: Needed by signal.
	"""
	logging.info("Shutting down the server gracefully...")
	socketio.stop()
	print("Done, exiting")
	sys.exit(0)


# Register signal handler for graceful shutdown
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)


if __name__ == "__main__":
	main()