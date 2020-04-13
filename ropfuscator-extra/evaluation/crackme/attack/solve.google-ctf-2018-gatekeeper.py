import sys
from angr_helper import *

def main():
    progpath, opt = parse_args(sys.argv)
    #enable_simgr_logging()
    import angr, claripy
    username = claripy.BVS('username', 8 * 16)
    password = claripy.BVS('password', 8 * 16)
    proj = angr_make_project(progpath)
    state = angr_make_state(proj, [progpath, username, password], opt)
    simgr = angr_make_simgr(proj, state, opt)
    set_mem_limit(simgr, 8192)
    simgr.explore(find=lambda s: b'Correct' in s.posix.dumps(1),
                  avoid=lambda s: b'DENIED' in s.posix.dumps(1))
    print(simgr)
    if len(simgr.found) > 0:
        simgr = angr_make_simgr(proj, simgr.found[0], opt)
        simgr.run()
        print(simgr.deadended[0].posix.dumps(1))
        exit(0)
    if len(simgr.errored) > 0:
        print(simgr.errored[0])
        exit(1)

if __name__ == '__main__':
    main()
