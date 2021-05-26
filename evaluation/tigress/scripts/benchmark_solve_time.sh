#!/bin/bash

SCRIPT_PATH=$( (cd $(dirname $0) && pwd))

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <directory_with_tigress_samples>"
    exit
fi

for vanilla_sample in $(find $1 -maxdepth 1 -type f -name "vanilla-tigsam*"); do
    echo "Evaluating $vanilla_sample..."

    # The time is measured in elapsed real seconds
    \time -f "%C, %e" -a -o angr_solve_times.csv python $SCRIPT_PATH/solve_tigress_chall.py $vanilla_sample
done
