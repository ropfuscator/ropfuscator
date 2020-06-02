import argparse
import r2pipe

decompilers = {
    'r2dec':  'pdd',
    'ghidra': 'pdg',
}

ap = argparse.ArgumentParser()
ap.add_argument('decompiler', choices=decompilers.keys())
ap.add_argument('program')
ap.add_argument('-o', '--output', default='')
args = ap.parse_args()

if args.output == '':
    args.output = '{}.{}.c'.format(args.program, args.decompiler)

decomp_cmd = decompilers[args.decompiler]

common_funcs = [
    'sym.__x86.get_pc_thunk.ax',
    'sym.__x86.get_pc_thunk.bx',
    'sym.__x86.get_pc_thunk.cx',
    'sym.__x86.get_pc_thunk.dx',
    'sym.__do_global_dtors_aux',
    'sym._init',
    'sym._fini',
    'sym.__libc_csu_init',
    'sym.__libc_csu_fini',
    'sym.register_tm_clones',
    'sym.deregister_tm_clones',
    'entry0',
    'entry.init0',
]

r = r2pipe.open(args.program)
r.cmd('aaaa')
funcs = r.cmdj('aflj')

with open(args.output, 'w') as f:
    for func in funcs:
        name = func['name']
        if name in common_funcs or name.rfind('sym.imp.', 0) == 0 or name.rfind('loc.imp.', 0) == 0:
            continue
        r.cmd('s {}'.format(name))
        print('Decompiling {}'.format(name))
        f.write(r.cmd(decomp_cmd))
    print('Decompile complete: {}'.format(args.output))

r.quit()
