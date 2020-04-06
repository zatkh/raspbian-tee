#!/bin/bash

if [ $# -eq 0 ];then
	echo "No file specified"
	exit
fi

getfattr -m ^security --dump -e text "$1"
