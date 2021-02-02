#!/bin/bash
tests=("test1" "test2" "test3" "test4" "test5" "test6")
for test in "${tests[@]}"; do
	./tripwire --config testdata/${test}/config.yml > testdata/${test}/stdout.log 2> testdata/${test}/stderr.log
done
