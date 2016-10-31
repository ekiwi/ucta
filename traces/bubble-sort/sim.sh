#!/usr/bin/env bash

# r3,r5,r6,r7 are pushed to the stack before they are
# accessed for the first time
../sim-trace.py pc target.elf r3=0 lr=0 r7=0 r6=0 r5=0
