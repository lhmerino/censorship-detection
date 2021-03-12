#!/bin/bash
go build -o bin/tripwire ./cmd/tripwire/...
tests=("test1" "test2" "test3" "test4" "test5" "test6")
for test in "${tests[@]}"; do
	bin/tripwire --config testdata/${test}/config.yml > testdata/${test}/stdout.log 2> testdata/${test}/stderr.log
done
