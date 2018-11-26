#!/bin/bash
pyflakes ./samson | grep -vP "local variable '_.*' is assigned to but never used"