#!/usr/bin/env bash

# initialize the r4,r5,r6,lr registers to some dummy value
# as the call to fib in main will save and restore them
../sim-trace.py pc target-fw.elf sp=0x10000bc0 r14=0 r6=0 r5=0 r4=0
