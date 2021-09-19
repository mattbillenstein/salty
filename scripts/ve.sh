#!/bin/bash

pushd "$(dirname "$0")/.." > /dev/null
SCRIPTPATH="$(pwd)"
popd > /dev/null

python3 -m venv ve
source ve/bin/activate
pip install -U pip
pip install -r $SCRIPTPATH/requirements.txt
