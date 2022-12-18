#!/bin/bash

set -e
trap "exit" INT

curl -sSfx http://127.0.0.1:1081 -o /dev/null -U username:password http://example.com
curl -sSfx http://127.0.0.1:1081 -o /dev/null -U username:password https://example.com
curl -sSfx http://127.0.0.1:1081 -o /dev/null -U username:password https://example.com
echo "Success"
