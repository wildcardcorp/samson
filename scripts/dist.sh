#!/bin/bash
#pypy3 -m unittest discover tests/
rm dist/*
python3 setup.py sdist
twine upload dist/*
