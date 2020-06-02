import sys
from angr_helper import *

def main():
    progpath, opt = parse_args(sys.argv)
    #enable_simgr_logging()
    import angr, claripy
    proj = angr_make_project(progpath)
    arg = claripy.BVS('input', 8*16, explicit_name=True)
    state = angr_make_state(proj, [progpath, arg], opt)
    simgr = angr_make_simgr(proj, state, opt)
    set_mem_limit(simgr, 8192)
    simgr.explore(find=lambda s: len(s.posix.dumps(1)) > 0)
    print(simgr)
    if len(simgr.found) > 0:
        print(simgr.found[0].solver.eval(arg).to_bytes(16, 'big'))
        exit(0)
    if len(simgr.errored) > 0:
        print(simgr.errored[0])
        exit(1)

if __name__ == '__main__':
    main()

