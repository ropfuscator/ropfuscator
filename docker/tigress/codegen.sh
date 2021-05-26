#!/bin/bash

mkdir -p output/vanilla
mkdir -p output/obfuscated

for loopsize in $(seq 10 10 200); do
    tigress $TIGRESS_RANDOM_FUNS_ARGS \
        --RandomFunsLoopSize=$loopsize \
        --out=vanilla-tigsam-$loopsize.c \
        empty_template.c

    # tigress $TIGRESS_OBFUSCATION_ARGS \
    # --out=obf-tigsam-$loopsize.c \
    # vanilla-tigsam-$loopsize.c
done

mv vanilla-*.c output/vanilla
# mv obf-*.c output/obfuscated

# compress into final archive
tar -zcf tigress_samples.tar.gz output
