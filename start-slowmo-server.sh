#!/usr/bin/env bash
set -e

if [ ! -z $DEBUG ]; then
    set -x
fi

ncpu=$(nproc --all)
gomaxprocs=`expr ${ncpu} / 2`
cpu_list_start=0
cpu_list_end=`expr ${gomaxprocs} - 1`
GOMAXPROCS=${gomaxprocs} taskset -c "${cpu_list_start}-${cpu_list_end}" ./slowmo-server