#!/bin/bash

process="java"
max_cpu=95
max_mem=80

cpu=$(top -b -n1 -o +%CPU | grep $process | head -1 | awk '{print $9}')
pid1=$(top -b -n1 -o +%CPU | grep $process | head -1 | awk '{print $1}')
if [[ ! -z "$pid1" ]]
then
    # cpu check
    result=${cpu/.*}
    if [[ $result -gt $max_cpu ]]
    then
        kill -9 $pid1
    fi
fi

mem=$(top -b -n1 -o +%MEM | grep $process | head -1 | awk '{print $10}')
pid2=$(top -b -n1 -o +%MEM | grep $process | head -1 | awk '{print $1}')
if [[ ! -z "$pid2" ]]
then
    # mem check
    result=${cpu/.*}
    if [[ $result -gt $max_mem ]]
    then
        kill -9 $pid2
    fi
fi