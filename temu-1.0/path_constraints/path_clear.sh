#!/bin/sh

ls -al | grep $1 | tr -s ' ' | cut -d ' ' -f 8 | xargs rm -f 
