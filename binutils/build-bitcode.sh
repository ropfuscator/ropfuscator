#!/bin/sh

docker build -t binutils-llvm-bc .
docker run binutils-llvm-bc tar c . | tar x

