
TARGETS="crackme1 crackme2"
CONFIGS="plain roponly opaque stegano"

SCRIPT_DIR="$(dirname $0)"
STATIC_SCRIPT_DIR="$SCRIPT_DIR/../staticanalysis"

if [ $# -lt 1 ]; then
    echo Usage: $0 '<bin-dir>'
    exit 1
fi

BIN_DIR="$1"

run_decompile() {
    target=$1
    for config in $CONFIGS; do
	/usr/bin/env python3 $STATIC_SCRIPT_DIR/decompile-r2.py r2dec $BIN_DIR/eval.$target.$config
	/usr/bin/env python3 $STATIC_SCRIPT_DIR/decompile-r2.py ghidra $BIN_DIR/eval.$target.$config
	/usr/bin/env python3 $STATIC_SCRIPT_DIR/decompile-retdec.py $BIN_DIR/eval.$target.$config
    done
}

run_imm_operand_reverse() {
    target=$1
    for config in $CONFIGS; do
	/usr/bin/env python3 $STATIC_SCRIPT_DIR/reverse_imm_operands.py $BIN_DIR/eval.$target.$config > $BIN_DIR/eval.$target.$config.immoperand.txt
    done
}

for target in $TARGETS; do
    run_imm_operand_reverse $target
done

for target in $TARGETS; do
    run_decompile $target
done
