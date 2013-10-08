#!/bin/sh
find -name '*.py' | tee /dev/stderr | xargs pep8
