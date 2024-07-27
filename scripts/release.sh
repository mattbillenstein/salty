#!/bin/bash

set -eo pipefail

# include the v in version here - v0.3.0
gh release create "$1" --notes "$2" dist/salty-*

# macos machines, build.sh --clean and then
# gh release upload v0.3.0 dist/salty-macos-*
