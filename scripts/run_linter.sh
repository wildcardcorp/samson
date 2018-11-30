#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
pyflakes $DIR/../samson | grep -vP "local variable '_.*' is assigned to but never used"
pyflakes $DIR/../tests | grep -vP "local variable '_.*' is assigned to but never used"