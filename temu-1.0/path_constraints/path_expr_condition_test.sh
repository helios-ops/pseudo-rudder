#!/bin/sh

ls -al | grep $1 | grep -v '~' | tr -s ' ' | cut -d' ' -f 8 | xargs grep "AND" -c 
