#!/bin/sh

ROPF_DIR=$(dirname $0)/..

docker build -t ropfuscator:prebuild --target prebuild -f ${ROPF_DIR}/docker/Dockerfile ${ROPF_DIR}
docker build -t ropfuscator:build --target build -f ${ROPF_DIR}/docker/Dockerfile ${ROPF_DIR}
docker build -t ropfuscator:release --target runtime -f ${ROPF_DIR}/docker/Dockerfile