#!/bin/sh

# pep8.sh
#
# The Unix shell script I used in order to validate the Python source code of
# the project for PEP-8 standard conformity.
#
# Usage:
#   ./pep8.sh

find -name '*.py' | tee /dev/stderr | xargs pep8
