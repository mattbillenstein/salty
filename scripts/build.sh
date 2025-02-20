#!/bin/bash

set -eo pipefail

pushd "$(dirname "$0")/.." > /dev/null
SCRIPTPATH="$(pwd)"
popd > /dev/null

source activate
pyinstaller --onefile salty.py

OS="$(uname -s | tr '[:upper:]' '[:lower:]' | sed -e 's/darwin/macos/')"
ARCH="$(uname -m | sed -e 's/x86_64/amd64/')"
mv dist/salty dist/salty-$OS-$ARCH
