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

echo "ROPCC" $*

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
SRCARGS=""
OBJARGS=""
LIBARGS=""
LLC_ARGS=""
LD_ARGS=""
LINKER=1
SHOW_VERSION=0
OUTFILE=""

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
    *)
	ROPF_COMPILER=$ROPF_CXX
	ROPF_FINAL_LINKER=$GXX
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
	    shift
	    ;;
	*.c|*.cpp|*.cxx|*.cc|*.c++|*.C|*.h|*.hpp|*.hxx|*.hh|*.h++|*.H)
	    SRCARGS="$SRCARGS $1"
	    shift
	    ;;
	*.a)
	    LIBARGS="$LIBARGS $1"
	    shift
	    ;;
	*)
	    ARGS="$ARGS $1"
	    HAS_INPUT=1
	    shift
	    ;;
    esac
done

if [ "1" = "$SHOW_VERSION" -a "x" = "x$OBJARGS$SRCARGS" ]; then
    $ROPF_LLC --version
    exit 0
fi

if [ "x" = "x$OBJARGS$SRCARGS" ]; then
    echo Error: no input files.
    exit 1
fi

if [ "1" = "$LINKER" ]; then
    # Compile and link (or link only)
    LD_LIB_ARGS=""
    if [ "x" != "x$LIBARGS" ]; then
	# Link library (*.a)
	# extract bitcode files
	echo "=== ROPfuscator Extract Library ==="
	TMPOBJDIRS=""
	EXTRACTED_BC_OBJS=""
	for lib in $LIBARGS; do
	    TMPOBJDIR=$(mktemp -d)
	    OLD_DIR=$(pwd)
	    lib=$(realpath $lib)
	    cd $TMPOBJDIR
	    ar x $lib
	    cd $OLD_DIR
	    IS_NATIVELIB=0
	    for obj in $TMPOBJDIR/*.o; do
		case $(file $obj) in
		    *"LLVM IR bitcode"*)
			EXTRACTED_BC_OBJS="$EXTRACTED_BC_OBJS $obj"
			;;
		    *"ELF"*)
			IS_NATIVELIB=1
			;;
		esac
	    done
	    if [ "1" = "$IS_NATIVELIB" ]; then
		rm -rf $TMPOBJDIR
		LD_LIB_ARGS="$LD_LIB_ARGS $lib"
	    else
		TMPOBJDIRS="$TMPOBJDIRS $TMPOBJDIR"
	    fi
	done
    fi
    if [ "x" = "x$OUTFILE" ]; then
	OUTFILE=a.out
    fi
    if [ "x" != "x$SRCARGS" ]; then
	# Compile and link (source code)
	OUTOBJS=""
	for src in $SRCARGS; do
	    echo "=== ROPfuscator LLVM Compiler ==="
	    echo "$ROPF_COMPILER -emit-llvm -c $src $ARGS -o $src.o"
	    $ROPF_COMPILER -emit-llvm -c $src $ARGS -o $src.o
	    OUTOBJS="$OUTOBJS $src.o"
	done
	if [ "x" != "x$LIBARGS" ]; then
	    OUTOBJS="$OUTOBJS $EXTRACTED_BC_OBJS"
	fi
	echo "=== ROPfuscator Linker ==="
	echo "$ROPF_LLVMLINK $OUTOBJS -o $OUTFILE.linked.bc"
	$ROPF_LLVMLINK $OUTOBJS -o $OUTFILE.linked.bc
	echo "$ROPF_LLC $LLC_ARGS -o $OUTFILE.linked.s $OUTFILE.linked.bc"
	$ROPF_LLC $LLC_ARGS -o $OUTFILE.linked.s $OUTFILE.linked.bc
	echo "$ROPF_FINAL_LINKER -o $OUTFILE $OUTFILE.linked.s $LD_LIB_ARGS $LD_ARGS $ARGS"
	$ROPF_FINAL_LINKER -o $OUTFILE $OUTFILE.linked.s $LD_LIB_ARGS $LD_ARGS $ARGS
    else
	# Link only (no source code)
	echo "=== ROPfuscator Linker ==="
	if [ "x" != "x$LIBARGS" ]; then
	    OBJARGS="$OBJARGS $EXTRACTED_BC_OBJS"
	fi
	echo "$ROPF_LLVMLINK $OBJARGS -o $OUTFILE.linked.bc"
	$ROPF_LLVMLINK $OBJARGS -o $OUTFILE.linked.bc
	echo "$ROPF_LLC $LLC_ARGS -o $OUTFILE.linked.s $OUTFILE.linked.bc"
	$ROPF_LLC $LLC_ARGS -o $OUTFILE.linked.s $OUTFILE.linked.bc
	echo "$ROPF_FINAL_LINKER -o $OUTFILE $OUTFILE.linked.s $LD_LIB_ARGS $LD_ARGS $ARGS"
	$ROPF_FINAL_LINKER -o $OUTFILE $OUTFILE.linked.s $LD_LIB_ARGS $LD_ARGS $ARGS
    fi
else
    # Compile only (-c)
    if [ "x" = "x$OUTFILE" ]; then
	OUTFILE=${SRCARGS%.*}.o
    fi
    echo "=== ROPfuscator LLVM Compiler ==="
    echo "$ROPF_COMPILER -emit-llvm $SRCARGS $ARGS -o $OUTFILE"
    $ROPF_COMPILER -emit-llvm $SRCARGS $ARGS -o $OUTFILE
fi

if [ "x" != "x$TMPOBJDIR" ]; then
    rm -rf $TMPOBJDIR
fi
