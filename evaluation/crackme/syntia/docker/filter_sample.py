#!/usr/bin/env python2

import json
import sys

outreg  = sys.argv[1]
infile  = sys.argv[2]
outfile = sys.argv[3]

with open(infile, 'r') as f:
    data = json.load(f)

def filter_output(outputs):
    for key in list(outputs.keys()):
        if outputs[key]['location'] != outreg:
            del outputs[key]

filter_output(data['initial']['outputs'])
for key0 in data['sampling']:
    outputs = data['sampling'][key0]['outputs']
    filter_output(outputs)

with open(outfile, 'w') as f:
    json.dump(data, f, indent=4)
