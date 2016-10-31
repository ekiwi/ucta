#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# out of what ever reason, maybe because of shortcommings of the etm decoder
# or maybe because that is just the way the etm works, we sometimes
# (maybe even always...) get invalid pc values after 32bit instructions
# this script enumerates all instructions that were executed and gets rid
# of all pc values that do not point to the start of an insruction


import tempfile, subprocess, sys, r2pipe

if len(sys.argv) < 3:
	print("{} pc_file fw_elf".format(sys.argv[0]))
	sys.exit(1)

pc_inp = sys.argv[1]
fw     = sys.argv[2]

with open(pc_inp) as ff:
	pc_lines = ff.readlines()


addresses = sorted([int(line[3:].strip(), 16) for line in pc_lines])

intervals = []
start = 0
stop = 0
for addr in addresses:
	delta = addr - stop
	if delta in [2, 4]:
		stop = addr
	elif delta > 4:
		if stop > start: intervals.append((start, stop-start))
		start = addr
		stop = addr
if stop > start: intervals.append((start, stop-start))


r2 = r2pipe.open(fw)
valid_pc = []
for ii in intervals:
	pc = ii[0]
	end = ii[0] + ii[1]
	#print('0x{:08x} -> 0x{:08x}'.format(pc, end))
	while pc < end:
		valid_pc.append(pc)
		instr = r2.cmdj("pdj 1 @ 0x{:08x}".format(pc))[0]
		pc += instr['size']

for line in pc_lines:
	pc = int(line[3:].strip(), 16)
	if pc in valid_pc:
		print('PC 0x{:08x}'.format(pc))
