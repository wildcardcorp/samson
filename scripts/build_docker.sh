#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
podman build -f $DIR/Dockerfile -t samson:v0 $DIR/../