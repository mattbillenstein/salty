#!/bin/bash

set -eo pipefail

if [ "$1" == "--clean" ]; then
  git clean -xdf
  scripts/venv.sh
fi

pushd "$(dirname "$0")/.." > /dev/null
SCRIPTPATH="$(pwd)"
popd > /dev/null

source $SCRIPTPATH/.venv/bin/activate
pyinstaller --onefile salty.py

mv dist/salty dist/salty-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed -e 's/x86_64/amd64/')
