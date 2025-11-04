#!/bin/bash
source .venv/bin/activate
pip install -r requirements.txt

# Check if go is installed
if ! [ -x "$(command -v go)" ]; then
  echo 'Error: go is not installed.' >&2
  exit 1
fi

go install github.com/google/osv-scanner/cmd/osv-scanner@latest

python3 main.py "$@"
