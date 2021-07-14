#!/bin/sh
podman run -it -e PYTHONIOENCODING=utf-8 --mount type=bind,src=/,dst=/ localhost/samson:v0