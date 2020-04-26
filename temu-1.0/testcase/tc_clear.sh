#!/bin/sh

ls -al | grep testcase_ | tr -s ' ' | cut -d' ' -f 8 | xargs rm -f 
