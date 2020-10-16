from angr_helper import AngrHelper

def main():
    helper = AngrHelper()
    proj = helper.make_project()
    state = helper.make_state([helper.progpath])
    simgr = helper.make_simgr(state)
    helper.set_mem_limit(simgr, 8192)
    simgr.explore(find=lambda s: b'sum is' in s.posix.dumps(1))
    print(simgr)
    if len(simgr.found) > 0:
        print(simgr.found[0].posix.dumps(0))
        exit(0)
    if len(simgr.errored) > 0:
        print(simgr.errored[0])
        exit(1)

if __name__ == '__main__':
    main()
