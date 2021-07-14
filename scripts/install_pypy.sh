#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
dnf -y install pypy3 pypy3-devel gmp-devel redhat-rpm-config
ln -s $DIR/../samson /usr/lib64/pypy3-7.3/site-packages
pypy3 -m ensurepip
pypy3 -m pip install -r requirements.txt
