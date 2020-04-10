## tested with angr 8.20.1.7

def enable_simgr_logging():
    import logging
    logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

def help_and_exit(argv):
    print('Usage: {} <exe_path> <symbolic|tracing> <BFS|DFS> <eager|lazy>'.format(argv[0]))
    exit(1)

def parse_args(argv):
    if len(argv) < 5:
        help_and_exit(argv)
    progpath = argv[1]
    mode = argv[2]
    explore = argv[3]
    resolve = argv[4]
    if not (mode in ['symbolic', 'tracing']):
        help_and_exit(argv)
    if not (explore in ['BFS', 'DFS']):
        help_and_exit(argv)
    if not (resolve in ['eager', 'lazy']):
        help_and_exit(argv)
    return (progpath, {'mode': mode, 'explore': explore, 'resolve': resolve})

def angr_make_project(progpath):
    import angr
    import os
    # load executable
    ld_path = os.getenv('LD_LIBRARY_PATH')
    if ld_path:
        proj = angr.Project(progpath, ld_path=ld_path, use_system_libs=False)
    else:
        proj = angr.Project(progpath, use_system_libs=False)
    # workaround for angr/cle reloc bug
    for r in proj.loader.main_object.relocs:
        if r.resolvedby:
            # do relocation
            r.owner_obj.memory.pack_word(r.dest_addr, r.value)
    return proj

def angr_make_state(proj, args, options):
    import angr
    mode = options['mode'] # symbolic, tracing
    resolve = options['resolve'] # eager, lazy
    state = proj.factory.full_init_state(args=args, mode=mode)
    if mode == 'tracing':
        state.options.add(angr.options.USE_SYSTEM_TIMES)
    if resolve == 'lazy':
        state.options.add(angr.options.LAZY_SOLVES)
    return state

def angr_make_simgr(proj, state, options):
    import angr
    explore = options['explore'] # BFS, DFS
    simgr = proj.factory.simulation_manager(state)
    if explore == 'DFS':
        simgr.use_technique(angr.exploration_techniques.DFS())
    return simgr

def set_mem_limit(simgr, megabytes):
    import angr
    import resource, os, platform
    limit = megabytes * 1024 * (1024 if platform.system() == 'Darwin' else 1)
    class MemLimit(angr.ExplorationTechnique):
        def __init__(self, limit):
            self.limit = limit
        def step(self, simgr, stash='active', **kwargs):
            if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss > self.limit:
                raise MemoryError()
            simgr.step(stash=stash, **kwargs)
    simgr.use_technique(MemLimit(limit))
