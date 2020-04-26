#!/bin/sh

cd APIHooking_error_PathConstraint
ls -al | grep pc_ | tr -s ' ' | cut -d ' ' -f 8 | xargs rm -f 

cd ../APIHooking_error_testcase
ls -al | grep testcase_ | tr -s ' ' | cut -d ' ' -f 8 | xargs rm -f 

cd ../IRSYMEXE_error_PathConstraint
ls -al | grep pc_ | tr -s ' ' | cut -d ' ' -f 8 | xargs rm -f 

cd ../IRSYMEXE_error_testcase
ls -al | grep testcase_ | tr -s ' ' | cut -d ' ' -f 8 | xargs rm -f 


cd ..
rm -f err_path_dump
rm -f err_predicate_dump

ls -al | grep dbg_ | grep _expr | rm -f


ls -al | grep _trace_ | tr -s ' ' | cut -d ' ' -f 8 | xargs rm -f
ls -al | grep err_ | grep _tc | tr -s ' ' | cut -d ' ' -f 8 | xargs rm -f
