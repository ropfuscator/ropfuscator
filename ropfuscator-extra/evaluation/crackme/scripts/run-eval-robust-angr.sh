
TARGETS="crackme1 crackme2"
#TARGETS="crackme1 crackme2 defcon-quals-2016-amadhj defcon-quals-2016-baby-re defcon-quals-2017-magic google-ctf-2018-gatekeeper"
CONFIGS="plain roponly opaque-dummy opaque-multcomp opaque-dummy-branch-addreg opaque-dummy-branch-rdtsc opaque-dummy-branch-negstk opaque-multcomp-branch-addreg"

TIME_LOG="time.log"
EXEC_LOG="exec.log"

SCRIPT_DIR="$(dirname $0)"
ANGR_SCRIPT_DIR="$SCRIPT_DIR/../attack"
BIN_DIR="$1"

if [ "$BIN_DIR" = "" ]; then
   BIN_DIR=$SCRIPT_DIR/bin
fi

measure_time() {
    N=$1
    timefile=$2
    logfile=$3
    shift; shift; shift
    echo Running $N times: $*
    for i in $(seq 1 $N); do
	echo >> $logfile
	echo $* >> $logfile
	/usr/bin/env time --quiet -o /tmp/_time.tmp -f '%e\t%U\t%S\t%M\t%C' $* 2>>$logfile 1>>$logfile
	cat /tmp/_time.tmp >> $timefile
	rm /tmp/_time.tmp
    done
}

for target in $TARGETS; do
    for config in $CONFIGS; do
	measure_time 5 $TIME_LOG $EXEC_LOG /usr/bin/env python3 $ANGR_SCRIPT_DIR/solve-default.$target.py $BIN_DIR/eval.$target.$config
	measure_time 5 $TIME_LOG $EXEC_LOG /usr/bin/env python3 $ANGR_SCRIPT_DIR/solve-trace.$target.py $BIN_DIR/eval.$target.$config
    done
done

