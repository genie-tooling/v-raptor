#!/bin/bash

# Check for uv
if ! [ -x "$(command -v uv)" ]; then
  echo 'Error: uv is not installed. Please install it first.' >&2
  exit 1
fi

# Check for .venv and create if it doesn't exist
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment with uv..."
  uv venv
fi

source .venv/bin/activate
uv pip install .

# Check if go is installed
if ! [ -x "$(command -v go)" ]; then
  echo 'Error: go is not installed.' >&2
  exit 1
fi

go install github.com/google/osv-scanner/cmd/osv-scanner@latest

if [ "$1" == "start-web" ]; then
    python3 -m src.server
else
    python3 main.py "$@"
fi
