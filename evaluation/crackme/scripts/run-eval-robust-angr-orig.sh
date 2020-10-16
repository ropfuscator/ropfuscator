
TARGETS="crackme1 crackme2"
CONFIGS="plain roponly opaque stegano"

TIME_LOG="time.log"
EXEC_LOG="exec.log"
REPEAT=3
TIMEOUT=600

SCRIPT_DIR="$(dirname $0)"
ANGR_SCRIPT_DIR="$SCRIPT_DIR/../angr"
LIBC_DIR="/lib/i386-linux-gnu"

if [ $# -lt 1 ]; then
    echo Usage: $0 '<bin-dir>'
    exit 1
fi

BIN_DIR="$1"

measure_time() {
    N=$1
    timefile=$2
    logfile=$3
    shift 3
    echo Running $N times: $*
    for i in $(seq 1 $N); do
	echo >> $logfile
	echo $* >> $logfile
	/usr/bin/env time --quiet -o /tmp/_time.tmp -f '%e\t%U\t%S\t%M\t%C' timeout $TIMEOUT $* 2>>$logfile 1>>$logfile
	cat /tmp/_time.tmp >> $timefile
	rm /tmp/_time.tmp
    done
}

run_target() {
    target=$1
    angr_param1=$2
    angr_param2=$3
    angr_param3=$4
    for config in $CONFIGS; do
	measure_time $REPEAT $TIME_LOG $EXEC_LOG /usr/bin/env python3 $ANGR_SCRIPT_DIR/solve.$target.py $BIN_DIR/eval.$target.$config $angr_param1 $angr_param2 $angr_param3 --libdir $LIBC_DIR
    done
}

for target in $TARGETS; do
    run_target $target symbolic DFS eager
    run_target $target tracing DFS eager
    run_target $target symbolic BFS eager
    run_target $target tracing BFS eager
done
