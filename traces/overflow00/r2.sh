#!/usr/bin/env bash

ii=$(../extract-traced-mem-segs.py pc)
r2 -i $ii target.elf
