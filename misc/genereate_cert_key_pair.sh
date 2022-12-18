#!/bin/bash

set -e
trap "exit" INT

go run "$GOROOT/src/crypto/tls/generate_cert.go" --host localhost,127.0.0.1,::1 -duration 1000000h -ecdsa-curve P256
mv cert.pem tls_test_cert.pem
mv key.pem tls_test_key.pem
