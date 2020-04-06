#!/bin/bash

dirlist="/lib /lib64 /usr /bin /sbin /etc"
label="0;|65535;"

if [ $# -eq 1 ];then
	dirlist="$1"
fi

if [ $# -eq 2 ];then
	dirlist="$1"
	label="$2"
fi

for d in "$dirlist"; do
	find $d -exec /usr/bin/setfattr -n security.difc -v "$label" '{}' \; 
done

