#!/bin/sh

mkdir -p work

BIN_PATH=bin/eval.crackme3.stegano
ARGS=aaa
FUNC=g
echo python3 tracer.py -o work/trace.bin -n 10000 -f ${FUNC} ${BIN_PATH} ${ARGS}
python3 tracer.py -o work/trace.bin -n 10000 -f ${FUNC} ${BIN_PATH} ${ARGS}

docker build -t syntia docker
docker run -v "$(pwd)":/usr/src/syntia/mounted syntia sh /usr/src/syntia/mounted/docker/test.sh

