#!/bin/bash
pypy3 -m unittest discover tests/
python3 setup.py sdist
twine upload dist/*