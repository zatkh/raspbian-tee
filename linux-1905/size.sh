#!/bin/bash
LOGNAME=$1
TOP=$2

KERNEL_SYMBOLS=$LOGNAME-symbols
DIFF_SYMBOLES=$LOGNAME-diffsym
BUILTIN=*/built-in.a
NAME=built-in.a
RESULTS_DIR=results

mkdir -p $RESULTS_DIR 

echo -e "********TOTAL***********\n" >> $RESULTS_DIR/$LOGNAME
size vmlinux >> $RESULTS_DIR/$LOGNAME
echo -e "********GENERAL***********\n" >> $RESULTS_DIR/$LOGNAME
size $BUILTIN | sort -n -r -k 4 >> $RESULTS_DIR/$LOGNAME
echo -e "********MORE***********\n" >> $RESULTS_DIR/$LOGNAME
find . -name $NAME | xargs size | sort -n -r -k 4 >> $RESULTS_DIR/$LOGNAME

nm --size -r vmlinux >> $RESULTS_DIR/$KERNEL_SYMBOLS

echo -e "********top $TOP ***********\n" >> $RESULTS_DIR/$KERNEL_SYMBOLS-$TOP

nm --size -r vmlinux | head -$TOP >> $RESULTS_DIR/$KERNEL_SYMBOLS-$TOP

#mkdir -p kernel_pools
#cp vmlinux kernel_pools
#./scripts/bloat-o-meter $OLD_KERNEl $NEW_KERNEL
