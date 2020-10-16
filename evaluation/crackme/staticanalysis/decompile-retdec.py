import argparse
import importlib, os, sys

RETDEC_PYTHON_PATH='/snap/retdec/current/bin/retdec-decompiler.py'

ap = argparse.ArgumentParser()
ap.add_argument('program')
ap.add_argument('-o', '--output', default='')
ap.add_argument('--preserve-temps', default=False, const=True, nargs='?')
ap.add_argument('--retdec-path', metavar='path', default=RETDEC_PYTHON_PATH)
args = ap.parse_args()

if args.output == '':
    args.output = '{}.retdec.c'.format(args.program)

tempfiles = [args.output + postfix for postfix in ['.backend.bc', '.backend.ll', '.json', '.frontend.dsm']]

RETDEC_PYTHON_PATH=args.retdec_path

sys.path.insert(1, os.path.dirname(RETDEC_PYTHON_PATH))

retdec_spec = importlib.util.spec_from_file_location('retdec-decompiler', RETDEC_PYTHON_PATH)
retdec = importlib.util.module_from_spec(retdec_spec)
retdec_spec.loader.exec_module(retdec)

decompiler = retdec.Decompiler([args.program, '-o', args.output])
result = decompiler.decompile()

if not args.preserve_temps:
    for path in tempfiles:
        if os.path.isfile(path):
            os.remove(path)

exit(result)
