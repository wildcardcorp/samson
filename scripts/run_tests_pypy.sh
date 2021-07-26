#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

PYTEST=$(which pytest)
if [ "$?" -ne "0" ]
then
  PYTEST=$(which pytest-3)
fi

USE_COLOR=0 pypy3 $PYTEST --doctest-modules --ignore=$DIR/../tests/ $DIR/../samson
pypy3 -m unittest discover $DIR/../tests/
