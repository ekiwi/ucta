#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This file contains the core class of ucta, the micro controller trace analysis
framework.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Copyright 2016 by Kevin Läufer <kevin.laeufer@rwth-aachen.de>
"""


import re, sys
from thumb2 import Thumb2Execution
from esil import EsilExecution
from memory import Memory, Rom, Ram, PeripheralMemory, RegisterBank
from program import Program

class Ucta:
	def __init__(self, prog, mem, regs, ExecutionEngine):
		self.prog = prog
		self.print_instr = True
		self.print_regs  = True
		self.print_mem   = True
		#self.max_instr_count = 21
		#self.max_instr_count = 11286
		self.max_instr_count = 11526
		self.instr_count = 0
		self.exe = ExecutionEngine(mem, regs)
		self.mem = mem
		self.regs = regs

	def run(self, pc, fw):
		self.mem.set_print(print_mem=self.print_mem)
		with open(pc) as ff:
			last_instr = None
			for line in ff.readlines():
				if not line.startswith('PC '):
					print("Unknown line: {}".format(line))
					continue
				addr = int(line[3:].strip(), 16)
				instr = self.prog.read_instruction(addr)

				# update current instruction for a simple taint analysis
				self.mem.current_instruction = (self.instr_count, instr['opcode'])
				self.regs.current_instruction = (self.instr_count, instr['opcode'])
				# check if this is a plausible pc value
				if last_instr:
					if (instr['offset'] > last_instr['offset'] and
						instr['offset'] < last_instr['offset'] + last_instr['size']):
						raise Exception('Overlapping instructions @ pc=0x{:08x}:\n{}\n{}'.format(addr, last_instr, instr))
				#print(self.instr_count)
				if self.print_instr:
					print("\033[1m{: 6}: 0x{:02x}\033[0m: {}".format(
						self.instr_count, instr['offset'], instr['opcode']))
				self.exe.exec(instr)
				if self.print_regs: print(self.regs)
				self.instr_count += 1
				if self.instr_count >= self.max_instr_count:
					break
				last_instr = instr

	def quit(self):
		self.prog.close()

if __name__ == "__main__":
	# load command line arguments
	if len(sys.argv) < 4:
		print("{} pc_file fw_elf (reg=value)+".format(sys.argv[0]))
		sys.exit(1)

	pc = sys.argv[1]
	fw = sys.argv[2]

	prog = Program(fw)

	# build memory environment for stm32f407 target
	mem = Memory(
		Rom('flash',  bytes=1024 * 1024, start=0x08000000, prog=prog),
		Ram('ccm',    bytes=  64 * 1024, start=0x10000000),
		Ram('sram1',  bytes= 112 * 1024, start=0x20000000),
		Ram('sram2',  bytes=  16 * 1024, start=0x2001C000),
		Ram('backup', bytes=   4 * 1024, start=0x40024000),
		PeripheralMemory('apb1', bytes=  0x7fff, start=0x40000000),
		PeripheralMemory('apb2', bytes=  0x57ff, start=0x40010000),
		PeripheralMemory('ahb1', bytes= 0x5ffff, start=0x40020000),
		PeripheralMemory('ahb2', bytes= 0x60bff, start=0x50000000),
		PeripheralMemory('cortex-m4', bytes= 0xfffff, start=0xe0000000))
	regs = RegisterBank(16)

	# initialize registers if set via command line arguments
	load_sp_from_rom = True
	for reg in sys.argv[3:]:
		mm = re.match(r'(?P<reg>[rsplc\d+]+)=(?P<value>[a-fx\d]+)', reg)
		if mm:
			regs[mm.group('reg')] = int(mm.group('value'), 0)
			if mm.group('reg') == 13: load_sp_from_rom = False
		else:
			raise Exception("Invalid register init parameter `{}`. Try e.g. sp=0x123".format(reg))
	if load_sp_from_rom:
		sp = mem.read(0x08000000)
		print("initial stack pointer: 0x{:08x}".format(sp))
		regs['sp'] = sp

	#ucta = Ucta(prog, mem, regs, Thumb2Execution)
	ucta = Ucta(prog, mem, regs, EsilExecution)

	ucta.run(pc, fw)

	mem.print_known_content()

	ucta.quit()
