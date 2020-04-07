import angr
import claripy
import os
import sys

progpath = sys.argv[1]
ld_path = os.getenv('LD_LIBRARY_PATH')

if ld_path:
    proj = angr.Project(progpath, ld_path=ld_path, use_system_libs=False)
else:
    proj = angr.Project(progpath)

arg = claripy.BVS('input', 8*16, explicit_name=True)

state = proj.factory.full_init_state(args=[progpath, arg])
simgr = proj.factory.simulation_manager(state)

simgr.explore(find=lambda s: len(s.posix.dumps(1)) > 0)

print(simgr)
if len(simgr.found) > 0:
    print(simgr.found[0].solver.eval(arg).to_bytes(16, 'big'))
