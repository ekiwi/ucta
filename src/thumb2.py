#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This file contains the legacy thumb 2 execution engine

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


"""
## notes about ISA
* general purpose registers: `R0-R12`
* Temporary Work Register (`ip`): R12
* stack pointer: `R13`
* link register (return address): `R14`
* program counter: `R15`

for more information about asm syntax see:
http://www.ethernut.de/en/documents/arm-inline-asm.html
"""

import re, math

# parse opcode strings
re_reg_arg = re.compile(	# parses opcodes with up to 3 arguments
r'(?P<op>[a-z]+(\.w)?) ((?P<arg1>[a-flrxspi\d\-]+)(, (?P<arg2>[a-frxspi\d\-]+)(, (?P<arg3>[a-frxspi\d\-]+(, lsl [\d\-])?))?)?)?$')
re_ldr_str = re.compile(
r'(?P<op>((ldr)|(str))h?b?(\.w)?) (?P<reg>[r\d+]+), \[(?P<addr>[a-frxpsi\d]+)(, (?P<offset>[a-fxr\d]+(, lsl [\d\-])?))?\](?P<pre>!)?(, (?P<post>\d+))?$')
re_push_pop = re.compile(
r'(?P<op>(push)|(pop)) \{(?P<args>[a-frxlsp, \d]+)\}$')
re_ldm_stm = re.compile(
r'(?P<op>((ldm)|(stm))(\.w)?) (?P<reg>[r\d+]+)(?P<increment>!)?, \{(?P<args>[a-frxlsp, \d]+)\}$')
opregex = [re_reg_arg, re_ldr_str, re_push_pop, re_ldm_stm]


def parseop(op):
	for rr in opregex:
		m = rr.match(op)
		if m:
			dd = m.groupdict()
			if 'args' in dd:
				dd['args'] = dd['args'].split(", ")
			if 'arg1' in dd:
				args = [dd['arg1'], dd['arg2'], dd['arg3']]
				dd['args'] = [aa for aa in args if aa is not None]
			return dd
	raise Exception("ERROR: cannot parse opcode: `{}`".format(op))

# register to index
def r2i(name):
	if isinstance(name, int):
		return name
	elif re.match(r'r(\d)|(1\d)$', name):
		return int(name[1:])
	else:
		return {'ip':12, 'sp': 13, 'lr': 14, 'pc': 15}[name]

def is_reg(name):
	return re.match(r'((r(\d)|(1\d))|(sp)|(lr)|(pc)|(ip))$', name) is not None

# either read from register or return itermediate
re_lsl = re.compile(r'(?P<reg>[rsplc\d]+), lsl (?P<lsl>\d)$')

WordMax = (1<<32) - 1


class Thumb2Execution:
	def __init__(self, mem, regs):
		self.mem = mem
		self.R = regs
	def value(self, arg):
		if is_reg(arg):
			return self.R[arg]
		elif re_lsl.match(arg):
			m = re_lsl.match(arg).groupdict()
			return (self.R[m['reg']] << int(m['lsl'], 0)) & WordMax
		else:
			return int(arg, 0)

	def exec(self, offset, opcode):
		# 4 byte aligned pc used for address calculations
		pc = offset
		self.R[15] = pc + 4 if pc % 4 == 0 else pc + 2
		op = parseop(opcode)
		name = op['op'].strip('.w')	# `.w` only matters for the encoding, does not affect semantics
		args = op['args'] if 'args' in op else None
		if name.startswith('bl') or name in ['b', 'bne', 'bhs', 'beq', 'bx', 'bgt', 'bhi']:
			pass # skip branching instructions
		elif name in ['cmp']:
			pass # skip instructions that are currently nops in our coarse model
		elif name in ['ldr', 'ldrh', 'ldrb', 'str', 'strh', 'strb']:
			size = 'w' if name[-1] == 'r' else name[-1]
			addr = self.R[op['addr']]
			if op['offset'] is not None:
				addr += self.value(op['offset'])
			if name.startswith('ldr'):
				self.R[op['reg']] = self.mem.read(addr, size)
				# on_load(addr=addr, value=self.R[op['reg']], dst_reg=r2i(op['reg']), pc=pc, instr_count=instr_count)
			else:
				self.mem.write(addr, self.R[op['reg']], size)
				# on_store(addr=addr, value=self.R[op['reg']], src_reg=r2i(op['reg']), pc=pc, instr_count=instr_count)
			if op['post'] is not None:
				self.R[op['addr']] = self.R[op['addr']] + int(op['post'], 0)
			if op['pre'] is not None:   # the pre increment was already handled by the offset addition
				self.R[op['addr']] = addr    # but we still need to store the new address
		elif name == 'push':
			for rr in sorted((r2i(rr) for rr in args), reverse=True):
				self.mem.write(self.R[r2i('sp')], self.R[rr])
				# on_store(addr=self.R[r2i('sp')], value=self.R[rr], src_reg=r2i(rr), pc=pc, instr_count=instr_count)
				self.R[r2i('sp')] = self.R[r2i('sp')] - 4
		elif name == 'pop':
			for rr in sorted(r2i(rr) for rr in args):
				self.R[r2i('sp')] = self.R[r2i('sp')] + 4
				self.R[rr] = self.mem.read(self.R[r2i('sp')])
				# on_load(addr=self.R[r2i('sp')], value=self.R[rr], dst_reg=r2i(rr), pc=pc, instr_count=instr_count)
		elif name in ['stm', 'ldm']:
			addr = self.R[r2i(op['reg'])]
			for rr in sorted(r2i(rr) for rr in args):
				if name == 'stm':
					self.mem.write(addr, self.R[rr])
					# on_store(addr=addr, value=self.R[rr], src_reg=r2i(rr), pc=pc, instr_count=instr_count)
				else:
					self.R[rr] = self.mem.read(addr)
					# on_load(addr=addr, value=self.R[rr], dst_reg=r2i(rr), pc=pc, instr_count=instr_count)
				addr += 4
			if op['increment'] is not None:
				self.R[r2i(op['reg'])] = addr
		elif name.startswith('mov'):
			self.R[args[0]] = self.value(args[1])
		elif name in ['add', 'adds', 'sub', 'subs', 'lsl', 'lsls', 'orr', 'orrs', 'and', 'ands', 'asr', 'asrs']:
			name = name[:-1] if name[-1] == 's' else name
			operation = {
				'add': lambda a,b: a + b,
				'sub': lambda a,b: a - b,
				'lsl': lambda a,b: a << b,
				'asr': lambda a,b: a >> b,
				'orr': lambda a,b: a | b,
				'and': lambda a,b: a & b,
			}[name]
			if len(args) > 2:
				self.R[args[0]] = operation(self.value(args[1]), self.value(args[2])) & WordMax
			else:
				self.R[args[0]] = operation(self.value(args[0]), self.value(args[1])) & WordMax
		else:
			print("\033[31mTODO\033[0m: handle operation `{}`".format(op['op']))
