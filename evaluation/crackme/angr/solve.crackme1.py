from angr_helper import AngrHelper

def main():
    helper = AngrHelper()
    # helper.enable_simgr_logging()
    import claripy
    arg = claripy.BVS('input', 8*16, explicit_name=True)
    helper.make_project()
    state = helper.make_state([helper.progpath, arg])
    simgr = helper.make_simgr(state)
    helper.set_mem_limit(simgr, 8192)
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

