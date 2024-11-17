#!/bin/bash

pushd "$(dirname "$0")/.." > /dev/null
SCRIPTPATH="$(pwd)"
popd > /dev/null

/usr/bin/python3 -m venv $SCRIPTPATH/.venv
source $SCRIPTPATH/.venv/bin/activate
pip install -U pip
pip install -r $SCRIPTPATH/requirements.txt
