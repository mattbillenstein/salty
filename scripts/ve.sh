#!/bin/bash

python3 -m venv ve
source ve/bin/activate
pip install -U pip
pip install -r requirements.txt
