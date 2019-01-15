#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
pypy3 -m cProfile -s tottime -o $DIR/performance/last_run.pstats $DIR/performance/profiler_runner.py --test-path $DIR/../tests/$1/ --test-pattern test_$2*
python3 `which gprof2dot` -f pstats $DIR/performance/last_run.pstats | dot -Tsvg -o $DIR/performance/last_run.svg
xdg-open $DIR/performance/last_run.svg