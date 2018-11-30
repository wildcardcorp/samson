#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
python3 -m unittest discover --pattern *test*.py $DIR/../tests/