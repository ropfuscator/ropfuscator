#!/usr/bin/env python3


import angr
import claripy
import re
import logging
import sys
from pathlib import Path

logging.getLogger("angr.sim_manager").setLevel(logging.DEBUG)

OUTPUT_RE = re.compile(b"^[0-9]+$")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <tigress_executable>")
        exit(0)

    if not Path(sys.argv[1]).exists():
        print("The file does not exist!")
        exit(1)

    ac_bvs = claripy.BVS("activation_code", 64)

    p = angr.Project(sys.argv[1])
    state = p.factory.full_init_state(
        args=[f"{sys.argv[1]}", ac_bvs], mode="tracing")

    simgr = p.factory.simgr(state)

    simgr.explore(find=lambda s: OUTPUT_RE.match(s.posix.dumps(1)) is not None,
                  avoid=lambda s: b"Expired" in s.posix.dumps(1))

    if simgr.found:
        print(f"Win: {simgr.found[0].posix.dumps(1)}")
        print(f"Input: {simgr.found[0].solver.eval(ac_bvs, cast_to=bytes)}")


if __name__ == "__main__":
    main()
