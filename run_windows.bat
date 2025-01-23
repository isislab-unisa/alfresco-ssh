@echo off
REM Activate the virtual environment and run alfresco-ssh

if exist ".venv\" (
    call .venv\Scripts\activate
    python main.py --debug --port 8888
) else (
    echo The .venv does not exist.
    exit /b 1
)
