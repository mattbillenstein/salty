#!/bin/bash

pushd "$(dirname "$0")/.." > /dev/null
SCRIPTPATH="$(pwd)"
popd > /dev/null

rm -fR $SCRIPTPATH/.venv
/usr/bin/python3 -m venv $SCRIPTPATH/.venv
source $SCRIPTPATH/.venv/bin/activate
pip install -U pip
pip install -r $SCRIPTPATH/requirements.txt
