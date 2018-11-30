#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
# declare -a subfolders=("analyzers" "attacks")

# for i in "${subfolders[@]}"
# do
#    /usr/local/bin/sphinx-apidoc -o $DIR/../doc $DIR/../samson/$i/
# done
/usr/local/bin/sphinx-apidoc -o $DIR/../doc $DIR/../samson/

cd $DIR/../doc && make html