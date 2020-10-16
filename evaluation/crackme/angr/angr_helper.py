## tested with angr 8.20.1.7

import argparse

class AngrHelper:
    def __init__(self):
        ap = argparse.ArgumentParser()
        ap.add_argument('progpath', type=str, help='executable path to analyze')
        ap.add_argument('mode', choices=['symbolic', 'tracing'], help='choose simulation mode')
        ap.add_argument('explore', choices=['BFS', 'DFS'], help='choose exploration mode (breadth or depth first)')
        ap.add_argument('resolve', choices=['eager', 'lazy'], help='choose constraint solving mode')
        ap.add_argument('--libdir', type=str, help='libc directory path')
        ap.add_argument('--verbose', action='store_true', help='if set, log each step in simulation manager')
        ap.parse_args(namespace=self)
        if not self.libdir:
            import os
            self.libdir = os.getenv('LD_LIBRARY_PATH')
        if self.verbose:
            self.enable_simgr_logging()

    def enable_simgr_logging(self):
        import logging
        logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

    def make_project(self):
        import angr
        import os
        # load executable
        if self.libdir:
            proj = angr.Project(self.progpath, ld_path=self.libdir, use_system_libs=False)
        else:
            proj = angr.Project(self.progpath, use_system_libs=False)
        # workaround for angr/cle reloc bug
        for r in proj.loader.main_object.relocs:
            if r.resolvedby:
                # do relocation
                r.owner_obj.memory.pack_word(r.dest_addr, r.value)
        self.proj = proj
        return proj

    def make_state(self, args):
        import angr
        state = self.proj.factory.full_init_state(args=args, mode=self.mode)
        if self.mode == 'tracing':
            state.options.add(angr.options.USE_SYSTEM_TIMES)
        if self.resolve == 'lazy':
            state.options.add(angr.options.LAZY_SOLVES)
        return state

    def make_simgr(self, state):
        import angr
        simgr = self.proj.factory.simulation_manager(state)
        if self.explore == 'DFS':
            simgr.use_technique(angr.exploration_techniques.DFS())
        return simgr

    def explore(self, *args, **kwargs):
        return self.simgr.explore(*args, **kwargs)

    def set_mem_limit(self, simgr, megabytes):
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
