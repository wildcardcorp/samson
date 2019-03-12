#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

cd $DIR/../man
sphinx-build -b man -c $DIR/../doc -d _build/doctrees . artifacts