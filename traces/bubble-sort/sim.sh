#!/usr/bin/env bash


# r4 contains the length of our array which is 10
../sim-trace.py pc target-fw.elf sp=0x10000b88 r4=10 lr=0
