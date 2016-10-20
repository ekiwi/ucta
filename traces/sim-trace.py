#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This is a first, crappy atempt at simulating a trace in order to reproduce the
state on the target.

For the `fib` code example we will assume that all registers and ram locations
are zero when we start, except for `r` of cause which is the `pc`


## notes about ISA
* general purpose registers: `R0-R12`
* stack pointer: `R13`
* link register (return address): `R14`
* program counter: `R15`
"""


import re, math, sys
import r2pipe

if len(sys.argv) < 4:
	print("{} pc_file fw_elf stack_ptr_addr".format(sys.argv[0]))
	sys.exit(1)

pc = sys.argv[1]
fw = sys.argv[2]
init_sp = int(sys.argv[3], 16)

# load firmware image
r2 = r2pipe.open(fw)	# TODO: ugly global

class RegisterBank:
	def __init__(self):
		self.name = 'regs'
		self.data = [0] * 16
	def __getitem__(self, ii):
		return self.data[r2i(ii)]
	def __setitem__(self, ii, vv):
		self.data[r2i(ii)] = vv
	def __str__(self):
		return '[' + ', '.join('0x{:02x}'.format(dd) for dd in self.data) + ']'

class Ram:
	def __init__(self, name, size, offset, word_size=4):
		self.data = [0]*size
		self.offset = offset
		self.shift = int(math.log(word_size, 2))
	def addr_in_range(self, addr):
		return addr >= self.offset and addr < self.offset + len(self.data)
	def __getitem__(self, ii):
		return self.data[(ii - self.offset) >> self.shift]
	def __setitem__(self, ii, vv):
		self.data[(ii - self.offset) >> self.shift] = vv

class Rom:
	def __init__(self, name, size, offset):
		self.name = name
		self.offset = offset
		self.size = size
	def addr_in_range(self, addr):
		return addr >= self.offset and addr < self.offset + self.size
	def __getitem__(self, ii):
		return r2.cmdj("pfj x @ {}".format(ii))[0]['value']
	def __setitem__(self, ii, vv):
		raise Exception('Cannt write to Read Only Memory.')

class Memory:
	def __init__(self, *sections):
		self.sections = sections
	def __getitem__(self, ii):
		for sec in self.sections:
			if sec.addr_in_range(ii):
				return sec[ii]
		raise Exception("Invalid read access to addr: 0x{:08x}".format(ii))

	def __setitem__(self, ii, vv):
		for sec in self.sections:
			if sec.addr_in_range(ii):
				sec[ii] = vv
				return
		raise Exception("Invalid write access to addr: 0x{:08x}".format(ii))


mem = Memory(
	Rom('flash',  size=1024 * 1024, offset=0x08000000),
	Ram('ccm',    size=  64 * 1024, offset=0x10000000),
	Ram('sram1',  size= 112 * 1024, offset=0x20000000),
	Ram('sram2',  size=  16 * 1024, offset=0x2001C000),
	Ram('backup', size=   4 * 1024, offset=0x40024000))

R = RegisterBank()

# parse opcode strings
re_reg_arg = re.compile(	# parses opcodes with up to 3 arguments
r'(?P<op>[a-z]+) ((?P<arg1>[a-frx\d]+)(, (?P<arg2>[a-frx\d]+)(, (?P<arg3>[a-frx\d]+))?)?)?$')
re_ldr_str = re.compile(
r'(?P<op>(ldr)|(str)) (?P<reg>[r\d+]+), \[(?P<addr>[a-frxps\d]+)(, (?P<offset>[a-fx\d]+))?\]$')
re_push_pop = re.compile(
r'(?P<op>(push)|(pop)) \{(?P<args>[a-frxlsp, \d]+)\}$')
opregex = [re_reg_arg, re_ldr_str, re_push_pop]


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
		return {'sp': 13, 'lr': 14, 'pc': 15}[name]

def is_reg(name):
	return re.match(r'(r(\d)|(1\d))|(sp)|(lr)|(pc)$', name) is not None

# itermediate to integer
def i2i(inp):
	if inp.startswith('0x'):
		return int(inp, 16)
	else:
		return int(inp)

# either read from register or return itermediate
def value(arg):
	return R[arg] if is_reg(arg) else i2i(arg)

def exec(instr):
	R[15] = instr['offset']
	op = parseop(instr['opcode'])
	name = op['op']
	args = op['args'] if 'args' in op else None
	if name.startswith('bl') or name in ['b']:
		pass # skip branching instructions
	elif name in ['cmp']:
		pass # skip instructions that are currently nops in our coarse model
	elif name in ['ldr', 'str']:
		if op['addr'] is None:
			# TODO: why do we need +4? where are we off by 1 (*4)?
			addr = R[15] + i2i(op['offset']) + 4
		else:
			addr = R[op['addr']]
		if name == 'ldr':
			R[op['reg']] = mem[addr]
		else:
			mem[addr] = R[op['reg']]
	elif name == 'push':
		for rr in sorted((r2i(rr) for rr in args), reverse=True):
			mem[R[r2i('sp')]] = R[rr]
			R[r2i('sp')] = R[r2i('sp')] - 4
	elif name == 'pop':
		for rr in sorted(r2i(rr) for rr in args):
			R[r2i('sp')] = R[r2i('sp')] + 4
			R[rr] = mem[R[r2i('sp')]]
	elif name.startswith('mov'):
		R[args[0]] = value(args[1])
	elif name.startswith('add'):
		if len(args) > 2:
			R[args[0]] = value(args[1]) + value(args[2])
		else:
			R[args[0]] = value(args[0]) + value(args[1])
	elif name.startswith('sub'):
		if len(args) > 2:
			R[args[0]] = value(args[1]) - value(args[2])
		else:
			R[args[0]] = value(args[0]) - value(args[1])
	else:
		print("TODO: handle operation `{}`".format(op['op']))

	print("0x{:02x}: {} => {}".format(instr['offset'], instr['opcode'], op))
	print("R: {}".format(R))





# load and execute instructions
max_instr_count = 30000
instr_count = 0
with open(pc) as ff:
	# TODO: this was read out with a debugger.... we actually need to calculate
	#       the value of the stack pointer, but this is only possible,
	#       when tracing from the beginning
	R[r2i('sp')] = init_sp
	for line in ff.readlines():
		if not line.startswith('PC '):
			print("Unknown line: {}".format(line))
			continue
		addr = line[3:].strip()
		print("{}: {}".format(instr_count, addr))
		exec(r2.cmdj("pdj 1 @ {}".format(addr))[0])
		instr_count += 1
		if instr_count >= max_instr_count:
			break

r2.quit()