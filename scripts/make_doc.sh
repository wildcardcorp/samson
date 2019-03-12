#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
/usr/local/bin/sphinx-apidoc -o $DIR/../doc $DIR/../samson/

cd $DIR/../doc && make html
$DIR/make_man.sh