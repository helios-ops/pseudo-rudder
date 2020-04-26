#!/bin/sh

ls -al | grep func_ | tr -s ' ' | cut -d' ' -f 8 | xargs rm -f
