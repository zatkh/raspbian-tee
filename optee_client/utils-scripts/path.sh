#!/bin/bash

if [ $# -eq 0 ] ;then
	echo "need inode number"
	exit
fi

CMD="ncheck $1"

debugfs -R "$CMD" /dev/vda1
