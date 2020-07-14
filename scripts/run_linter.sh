#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
autopep8 --select=W291,W293,W391 --in-place -r $DIR/../samson/
autopep8 --select=W291,W293,W391 --in-place -r $DIR/../tests/
flake8 --select=F,W,C90 --exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,all.py $DIR/../samson | grep -vP ".* W293 .*" | grep -vP ".* W605 .*" | grep -vP ".* W291 .*" | grep -vP ".* F841 local variable '_.*' is assigned.*" | grep -vP ".* F821 .*" | grep -vP ".* F405 .*"
flake8 --select=F,W,C90 --exclude=$DIR/../tests/primitives/test_ntru.py $DIR/../tests | grep -vP ".* F841 local variable '_.*' is assigned.*"