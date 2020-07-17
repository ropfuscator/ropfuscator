from angr_helper import AngrHelper

def main():
    helper = AngrHelper()
    import claripy
    username = claripy.BVS('username', 8 * 16)
    password = claripy.BVS('password', 8 * 16)
    helper.make_project()
    state = helper.make_state([helper.progpath, username, password])
    simgr = helper.make_simgr(state)
    helper.set_mem_limit(simgr, 8192)
    simgr.explore(find=lambda s: b'Correct' in s.posix.dumps(1),
                  avoid=lambda s: b'DENIED' in s.posix.dumps(1))
    print(simgr)
    if len(simgr.found) > 0:
        simgr = helper.make_simgr(simgr.found[0])
        simgr.run()
        print(simgr.deadended[0].posix.dumps(1))
        exit(0)
    if len(simgr.errored) > 0:
        print(simgr.errored[0])
        exit(1)

if __name__ == '__main__':
    main()
