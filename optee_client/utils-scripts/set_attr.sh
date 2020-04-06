#!/bin/bash

LABEL="1;3;4;5;|2;"
FILE="test4"

if [ $# -eq 1 ]; then
	FILE="$1"
fi

if [ $# -eq 2 ]; then
	LABEL="$1"
	FILE="$2"
fi

setfattr -n security.difc -v "$LABEL" "$FILE"
