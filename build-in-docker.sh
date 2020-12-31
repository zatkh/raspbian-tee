#!/bin/bash

set -e


cd docker
docker build -t sirius-builder .
cd -

DOCKER="docker run -it --rm -v $(pwd):$(pwd) -w $(pwd) -u $(id -u):$(id -g) sirius-builder"

$DOCKER ./prepare-env.sh || true # Ignore errors if packages already exists
$DOCKER make
