#!/bin/bash

set -eo pipefail

gh release create "$1" --notes "$2" dist/salty-*

# macos machines, build.sh --clean and then
# gh release upload v0.3.0 dist/salty-macos-*
