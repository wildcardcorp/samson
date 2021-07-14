#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
dnf -y install python3-devel gmp-devel redhat-rpm-config
ln -s $DIR/../samson /usr/local/lib64/python3.8/site-packages
pip3 install -r requirements.txt
