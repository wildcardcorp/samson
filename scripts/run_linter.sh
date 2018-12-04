#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
pyflakes $DIR/../samson | grep -vP "local variable '_.*' is assigned to but never used" | grep -vP ".* used; unable to detect undefined names" | grep -vP "'(samson)?\..*\..*' imported but unused"
pyflakes $DIR/../tests | grep -vP "local variable '_.*' is assigned to but never used"