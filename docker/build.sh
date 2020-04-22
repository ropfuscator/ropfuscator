#!/bin/sh

ROPF_DIR=$(dirname $0)/..

docker build -t ropfuscator:prebuild-llvm-7 --target prebuild -f ${ROPF_DIR}/docker/Dockerfile.llvm-7 ${ROPF_DIR}
docker build -t ropfuscator:build-llvm-7 --target build -f ${ROPF_DIR}/docker/Dockerfile.llvm-7 ${ROPF_DIR}
docker build -t ropfuscator:llvm-7 --target runtime -f ${ROPF_DIR}/docker/Dockerfile.llvm-7 ${ROPF_DIR}
