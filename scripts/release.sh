#!/bin/bash

set -eo pipefail

gh release create "$1" --notes "$2" dist/salty-*
