#!/bin/bash

set -e

docker build -f ./qa/Dockerfile.test -t cbtc/cbtc-test .
docker run -it --rm cbtc/cbtc-test ./qa/cbtc/full_test_suite.py
docker run -it --rm cbtc/cbtc-test ./qa/pull-tester/rpc-tests.sh
