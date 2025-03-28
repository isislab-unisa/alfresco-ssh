#!/bin/bash
# Activate the virtual environment and run alfresco-ssh

if [ -d ".venv" ]; then
  source .venv/bin/activate
  python3 main.py --debug --port 8888
else
  echo "The .venv does not exist."
  exit 1
fi
