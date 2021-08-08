#!/bin/bash

BASE_DIR="$(cd $(dirname ${BASH_SOURCE[0]})/..; pwd -P)"

cd "${BASE_DIR}/acceptance"

pipenv run pytest "$@"
