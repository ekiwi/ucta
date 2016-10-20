#!/usr/bin/env python3
# -*- coding: utf-8 -*-




import tempfile, subprocess, sys

if len(sys.argv) < 2:
	print("{} pc_file".format(sys.argv[0]))
	sys.exit(1)

pc = sys.argv[1]


with open(pc) as ff:
	addresses = sorted([int(line[3:].strip(), 16) for line in ff.readlines()])

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

#for ii in intervals:
#	print("0x{:08x} => 0x{:08x} ({})".format(ii[0], ii[0]+ii[1], ii[1]))

with tempfile.NamedTemporaryFile(mode='w', suffix=".r2", delete=False) as r2:
	print("aaaa", file=r2)
	for ii in intervals:
		print("s 0x{:08x}".format(ii[0]), file=r2)
		print("pD {}".format(ii[1] + 2),file=r2)
	r2_script = r2.name

print(r2_script)
