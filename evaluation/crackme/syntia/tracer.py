import argparse
import json
import os
import sys

import r2pipe

def main():
    ap = argparse.ArgumentParser(
        prog=sys.argv[0],
        description='run executable and generate instruction trace.')
    ap.add_argument('program', nargs=1,
                    help='executable file')
    ap.add_argument('args', nargs='*',
                    help='arguments to the program')
    ap.add_argument('-o', '--output', default='dump-trace.bin', nargs='?',
                    help='trace output file (default: dump-trace.bin)')
    ap.add_argument('-f', '--func', nargs='?',
                    help='function name to trace (default: main)')
    ap.add_argument('-a', '--addr', nargs='?',
                    help='function address to trace')
    ap.add_argument('-n', '--num-instr', metavar='N', default=1000, type=int, nargs='?',
                    help='max number of instructions to trace (default: 100)')
    ap.add_argument('-r', '--trace-after-return', action='store_true',
                    help='trace after function return')
    ap.add_argument('-q', '--quiet', action='store_true',
                    help='do not show debugger output')
    args = ap.parse_args()
    tr = Tracer(args.program[0], args=args.args, quiet=args.quiet)
    if args.func is None:
        if args.addr is None:
            func = 'sym.main'
        else:
            func = args.addr
    else:
        func = 'sym.' + args.func
    inst_bytes = tr.trace(func, args.num_instr, args.trace_after_return)
    outdir = '{}.dir'.format(args.output)
    os.makedirs(outdir, exist_ok=True)
    n = 0
    with open(args.output, 'wb') as f:
        for bs in inst_bytes:
            n += 1
            with open('{}/{:04d}.bin'.format(outdir, n), 'wb') as f1:
                bs = b''.join(bs)
                f.write(bs)
                f1.write(bs)

class Tracer:
    def __init__(self, filename, args=[], quiet=False):
        if quiet: self.r2flags = ['-2']
        else: self.r2flags = []
        self.prog = filename
        self.args = args

    def is_indirect_jump(self, inst):
        if inst['type'] == 'call' or inst['type'] == 'ret' or inst['type'] == 'rjmp' or inst['type'] == 'rcall':
            return True
        return False

    def trace(self, start, limit, trace_after_return=False):
        l = []
        inst_bytes = []
        r2 = r2pipe.open(self.prog, self.r2flags)
        r2.cmd('ood {}'.format(' '.join(self.args)))
        syms = r2.cmdj('isj')
        if 'sym.' in str(start):
            start = start[4:]
            names = [s['flagname'] for s in syms if s['realname'] == start and s['type'] == 'FUNC']
            if len(names) < 1:
                start = None
            else:
                start = names[0]
        if not (start is None):
            r2.cmd('dcu {}'.format(start))
        arch = r2.cmdj('iIj')
        arch = '{}_{}'.format(arch['arch'], arch['bits'])
        ip_regs = {'x86_32': 'eip', 'x86_64': 'rip'}
        sp_regs = {'x86_32': 'esp', 'x86_64': 'rsp'}
        ip_reg = ip_regs[arch]
        sp_reg = sp_regs[arch]
        base_sp = None
        while len(inst_bytes) < limit:
            st = {}
            try: regs = r2.cmdj('drj')
            except: regs = None
            if regs is None: break
            st['regs'] = regs
            ip = regs[ip_reg]
            if base_sp is None:
                base_sp = regs[sp_reg]
            if not trace_after_return and regs[sp_reg] > base_sp: break
            inst = r2.cmdj('pdj 1 @ {}'.format(ip_reg))[0]
            #print(inst)
            inst_bytes.append(bytes.fromhex(inst['bytes']))
            if self.is_indirect_jump(inst):
                l.append(inst_bytes)
                inst_bytes = []
                #print('===========================')
            r2.cmd('ds')
        r2.quit()
        if len(inst_bytes) > 0:
            l.append(inst_bytes)
        return l

if __name__ == '__main__':
    main()

