#!/bin/bash

output=`cat log | grep SYQ | mawk '{ split($8, A, ")"); print A[1]}' | sort -r -u`

while read -r line; do
	file=`./path.sh "$line"`
	echo "$file"
done <<< "$output"
