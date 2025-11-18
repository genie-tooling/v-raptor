#!/bin/bash

# Default values
USE_VENV=false
PYTHON_VERSION=""

# Parse arguments
for arg in "$@"
do
    case $arg in
        --venv)
        USE_VENV=true
        shift
        ;;
        --python-version=*)
        PYTHON_VERSION="${arg#*=}"
        shift
        ;;
    esac
done

if [ "$USE_VENV" = true ] ; then
    if [ -z "$PYTHON_VERSION" ]; then
        echo "Please specify a python version with --python-version"
        exit 1
    fi

    echo "Creating virtual environment with python $PYTHON_VERSION..."
    uv venv -p "$PYTHON_VERSION" .test_venv
    if [ $? -ne 0 ]; then
        echo "Failed to create virtual environment with python $PYTHON_VERSION"
        exit 1
    fi

    echo "Activating virtual environment..."
    source .test_venv/bin/activate

    echo "Installing dependencies..."
    uv pip sync pyproject.toml

    echo "Running tests..."
    pytest

    echo "Deactivating and removing virtual environment..."
    deactivate
    rm -rf .test_venv
else
    pytest
fi
