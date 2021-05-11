#!/bin/sh

ROPF_DIR=$(dirname $0)/..

docker build -t ropfuscator:prebuild-llvm-9 --target prebuild -f ${ROPF_DIR}/docker/Dockerfile.llvm-9 ${ROPF_DIR}
docker build -t ropfuscator:build-llvm-9 --target build -f ${ROPF_DIR}/docker/Dockerfile.llvm-9 ${ROPF_DIR}
docker build -t ropfuscator:llvm-9 --target runtime -f ${ROPF_DIR}/docker/Dockerfile.llvm-9 ${ROPF_DIR}
