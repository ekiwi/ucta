#!/usr/bin/env python3
# -*- coding: utf-8 -*-

fw = "target-fw.elf"
pc = "pc"

import r2pipe



r2 = r2pipe.open(fw)

with open(pc) as ff:
	for line in ff.readlines():
		if not line.startswith('PC '):
			print("Unknown line: {}".format(line))
			continue
		addr = line[3:].strip()
		instr = r2.cmdj("pdj 1 @ {}".format(addr))[0]
		#print("{}\n".format(instr))
		print("{}: {}".format(addr, instr['opcode']))


r2.quit()
