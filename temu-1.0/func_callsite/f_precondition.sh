#!/bin/sh

ls -al | grep func_ | grep -v '~' | tr -s ' ' | cut -d' ' -f 8 | xargs grep "precondition_" -c 
