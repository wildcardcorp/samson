#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
pypy3 `which pytest` --doctest-modules --ignore=$DIR/../tests/
pypy3 -m unittest discover $DIR/../tests/