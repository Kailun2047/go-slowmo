#!/usr/bin/env bash
set -e

if [ ! -z $DEBUG ]; then
    set -x
fi

ncpu=$(nproc --all)
gomaxprocs=`expr ${ncpu} / 2`
GOMAXPROCS=${gomaxprocs} ./exec-server