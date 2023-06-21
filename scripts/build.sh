#!/bin/bash

pushd "$(dirname "$0")/.." > /dev/null
SCRIPTPATH="$(pwd)"
popd > /dev/null

source $SCRIPTPATH/.venv/bin/activate
nuitka3 --follow-imports --output-filename="salty.$(uname -s)-$(uname -m)" salty.py
