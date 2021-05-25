import angr
import claripy
import re
import logging

logging.getLogger("angr.sim_manager").setLevel(logging.DEBUG)

OUTPUT_RE = re.compile(b"^[0-9]+$")

def main():
    ac_bvs = claripy.BVS("activation_code", 64)
    
    p = angr.Project("test.bin")
    state = p.factory.full_init_state(args=["test.bin", ac_bvs], mode="tracing")

    simgr = p.factory.simgr(state)

    simgr.explore(find=lambda s: OUTPUT_RE.match(s.posix.dumps(1)) is not None, avoid=lambda s: b"Expired" in s.posix.dumps(1))

    if simgr.found:
        print(f"Win: {simgr.found[0].posix.dumps(1)}")
        print(f"Input: {simgr.found[0].solver.eval(ac_bvs, cast_to=bytes)}")

if __name__ == "__main__":
    main()