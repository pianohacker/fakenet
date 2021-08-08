#!/bin/bash

BASE_DIR="$(cd $(dirname ${BASH_SOURCE[0]})/..; pwd -P)"

cd "${BASE_DIR}"

docker run \
	--rm \
	--mount type=bind,src=$PWD,dst=/mnt \
	--cap-add NET_ADMIN \
	--device=/dev/net/tun:/dev/net/tun:rw \
	--network=none \
	fakenet-acceptance /mnt/acceptance/docker-inner.sh "$@"
