#!/bin/bash

# This test script adds and removes routes from a local DV forwarder.
# This can be used to test a large number of changes to the RIB.

MAX_RIB_SIZE=3

ITER=0
while true; do
    ITER=$((ITER+1))

    RIB_SIZE=0
    while [ $RIB_SIZE -lt $MAX_RIB_SIZE ]; do
        RIB_SIZE=$((RIB_SIZE+1))
        ndnd fw route add prefix=/my/route/$RIB_SIZE/$ITER origin=65 face=1
        sleep 0.05
    done

    sleep 0.1

    RIB_SIZE=0
    while [ $RIB_SIZE -lt $MAX_RIB_SIZE ]; do
        RIB_SIZE=$((RIB_SIZE+1))
        ndnd fw route remove prefix=/my/route/$RIB_SIZE/$ITER origin=65 face=1
        sleep 0.05
    done
done