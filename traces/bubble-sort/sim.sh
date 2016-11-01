#!/usr/bin/env bash

# r4,r5,r6,r7 are pushed to the stack before they are
# accessed for the first time
../sim-trace.py pc target.elf lr=0 r4=0 r5=0 r6=0 r7=0
