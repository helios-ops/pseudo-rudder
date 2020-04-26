#!/bin/sh

rm -f tc_result
ls -al | grep "testcase_" | grep -v '~' | tr -s ' ' | cut -d' ' -f 8 | xargs od -t x1 ; sed -n '1p' - >> tc_result
