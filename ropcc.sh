#!/bin/sh

############################################################
## ROPfuscator Build Harness
##
## Usage:
##   ropcc.sh [cc|c++] [compile-options] -c foo.c -o foo.o
##       Compile source code to LLVM bitcode (obfuscation not performed)
##   ropcc.sh [cc|c++] [link-options] -ropfuscator-config=rop.conf foo.o bar.o -o exefile
##       Link/obfuscate several LLVM bitcode files
##       (execute llvm-link -> llc -> gcc/g++)
##   ropcc.sh -v
##       Show llc version information

# set path to ropfuscator binary directory
ROPF_BIN_DIR=/opt/ropfuscator/bin

ROPF_CC="$ROPF_BIN_DIR/clang -m32"
ROPF_CXX="$ROPF_BIN_DIR/clang++ -m32"
ROPF_LLC="$ROPF_BIN_DIR/llc"
ROPF_LLVMLINK="$ROPF_BIN_DIR/llvm-link"

GCC="gcc -m32 -pie"
GXX="g++ -m32 -pie"

ROPF_COMPILER=$ROPF_CC
ROPF_FINAL_LINKER=$GCC

ARGS=""
OBJARGS=""
LLC_ARGS=""
LD_ARGS=""
LINKER=1
HAS_INPUT=0
SHOW_VERSION=0
OUTFILE=a.out

case "$1" in
    cc)
	ROPF_COMPILER=$ROPF_CC
	ROPF_FINAL_LINKER=$GCC
	shift
	;;
    c++)
	ROPF_COMPILER=$ROPF_CXX
	ROPF_FINAL_LINKER=$GXX
	shift
	;;
esac

while [ $# -gt 0 ]; do
    case "$1" in
	-v|--version)
	    SHOW_VERSION=1
	    shift
	    ;;
	-c)
	    ARGS="$ARGS $1"
	    LINKER=0
	    shift
	    ;;
	-o)
	    OUTFILE=$2
	    shift
	    shift
	    ;;
	-mllvm)
	    LLC_ARGS="$LLC_ARGS $2"
	    shift
	    shift
	    ;;
	-ropfuscator-config=*)
	    LLC_ARGS="$LLC_ARGS $1"
	    shift
	    ;;
	-l*|-L*)
	    LD_ARGS="$LD_ARGS $1"
	    shift
	    ;;
	-*)
	    ARGS="$ARGS $1"
	    shift
	    ;;
	*.o)
	    OBJARGS="$OBJARGS $1"
	    HAS_INPUT=1
	    shift
	    ;;
	*)
	    ARGS="$ARGS $1"
	    HAS_INPUT=1
	    shift
	    ;;
    esac
done

if [ "1" -eq "$SHOW_VERSION" ]; then
    $ROPF_LLC --version
    exit 0
fi

if [ "0" -eq "$HAS_INPUT" ]; then
    echo Error: no input files.
    exit 1
fi

if [ "1" -eq "$LINKER" ]; then
    echo "=== ROPfuscator Linker ==="
    echo "$ROPF_LLVMLINK $OBJARGS -o $OUTFILE.linked.bc"
    $ROPF_LLVMLINK $OBJARGS -o $OUTFILE.linked.bc
    echo "$ROPF_LLC $LLC_ARGS -o $OUTFILE.linked.s $OUTFILE.linked.bc"
    $ROPF_LLC $LLC_ARGS -o $OUTFILE.linked.s $OUTFILE.linked.bc
    echo "$ROPF_FINAL_LINKER -o $OUTFILE $OUTFILE.linked.s $LD_ARGS"
    $ROPF_FINAL_LINKER -o $OUTFILE $OUTFILE.linked.s $LD_ARGS
else
    echo "=== ROPfuscator LLVM Compiler ==="
    echo "$ROPF_COMPILER -emit-llvm $ARGS -o $OUTFILE"
    $ROPF_COMPILER -emit-llvm $ARGS -o $OUTFILE
fi

