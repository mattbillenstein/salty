#!/bin/bash

#openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
  -subj "/C=US/ST=/L=/O=/CN=" \
  -keyout key.pem  -out cert.pem
openssl rand 1024 | openssl dgst -md5 | awk '{print $2}' > crypto.pass
