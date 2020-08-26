#!/bin/sh

CWD=$(dirname $0)
SYNTIA_DIR=$CWD/../..

python2 $SYNTIA_DIR/demo/random_sampling.py $SYNTIA_DIR/mounted/work/trace.bin x86_32 20 $SYNTIA_DIR/mounted/work/sample.json
python2 $CWD/filter_sample.py EAX $SYNTIA_DIR/mounted/work/sample.json $SYNTIA_DIR/mounted/work/sample2.json
python2 $SYNTIA_DIR/demo/sample_synthesis.py $SYNTIA_DIR/mounted/work/sample2.json $SYNTIA_DIR/mounted/work/result.json
