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


import re, math, sys, shutil
from enum import Enum
import r2pipe

if len(sys.argv) < 4:
	print("{} pc_file fw_elf (reg=value)+".format(sys.argv[0]))
	sys.exit(1)

pc = sys.argv[1]
fw = sys.argv[2]



# load firmware image
r2 = r2pipe.open(fw)	# TODO: ugly global

class MemState(Enum):
	unknown = 0
	concrete = 1
	symbolic = 2

class RegisterBank:
	def __init__(self):
		self.name = 'regs'
		self.data = [0] * 16
		self.state = [MemState.unknown] * 16
	def __getitem__(self, ii):
		ii = r2i(ii)
		if self.state[ii] == MemState.unknown:
			raise Exception("Cannot read from r{}: value unknown".format(ii))
		return self.data[ii]
	def __setitem__(self, ii, vv):
		self.state[r2i(ii)] = MemState.concrete
		self.data[r2i(ii)] = vv
	def __str__(self):
		cols = int(shutil.get_terminal_size((80, 20)).columns / 16)
		out = ''
		cc = 0
		for ii in range(0, len(self.data)):
			if cc >= cols:
				out += '\n'
				cc = 0
			if self.state[ii] == MemState.unknown: continue
			out += 'r{}: 0x{:08x}   '.format(ii, self.data[ii])
			cc += 1
		return out

class Ram:
	def __init__(self, name, size, offset, word_size=4):
		self.data = [0]*size
		self.state = [MemState.unknown] * size
		self.offset = offset
		self.shift = int(math.log(word_size, 2))
	def addr_in_range(self, addr):
		return addr >= self.offset and addr < self.offset + len(self.data)
	def __getitem__(self, addr):
		ii = (addr - self.offset) >> self.shift
		if self.state[ii] == MemState.unknown:
			raise Exception("Cannot read from addr 0x{:08x}: value unknown".format(addr))
		return self.data[ii]
	def __setitem__(self, addr, vv):
		ii = (addr - self.offset) >> self.shift
		self.state[ii] = MemState.concrete
		self.data[ii] = vv
	def print_known_content(self):
		for ii in range(0, len(self.data)):
			if self.state[ii] == MemState.unknown: continue
			addr = (ii << self.shift) + self.offset
			print('0x{:08x}: 0x{:08x}   '.format(addr, self.data[ii]))

class Rom:
	def __init__(self, name, size, offset):
		self.name = name
		self.offset = offset
		self.size = size
	def addr_in_range(self, addr):
		return addr >= self.offset and addr < self.offset + self.size
	def __getitem__(self, ii):
		hxdump = r2.cmd("pxw 4 @ {}".format(ii))
		vv = int(re.match(r'0x[a-f\d]+ +(?P<vv>0x[a-f\d]+)', hxdump).group('vv'), 16)
		return vv
	def __setitem__(self, ii, vv):
		raise Exception('Cannt write to Read Only Memory.')

class Memory:
	def __init__(self, *sections):
		self.sections = sections
	def __getitem__(self, ii):
		for sec in self.sections:
			if sec.addr_in_range(ii):
				vv = sec[ii]
				print("0x{:08x} => 0x{:08x}".format(ii, vv))
				return vv
		raise Exception("Invalid read access to addr: 0x{:08x}".format(ii))

	def __setitem__(self, ii, vv):
		for sec in self.sections:
			if sec.addr_in_range(ii):
				print("0x{:08x} <= 0x{:08x}".format(ii, vv))
				sec[ii] = vv
				return
		raise Exception("Invalid write access to addr: 0x{:08x}".format(ii))

	def print_known_content(self):
		for sec in self.sections:
			if isinstance(sec, Ram): sec.print_known_content()


mem = Memory(
	Rom('flash',  size=1024 * 1024, offset=0x08000000),
	Ram('ccm',    size=  64 * 1024, offset=0x10000000),
	Ram('sram1',  size= 112 * 1024, offset=0x20000000),
	Ram('sram2',  size=  16 * 1024, offset=0x2001C000),
	Ram('backup', size=   4 * 1024, offset=0x40024000))

R = RegisterBank()

# parse opcode strings
re_reg_arg = re.compile(	# parses opcodes with up to 3 arguments
r'(?P<op>[a-z]+) ((?P<arg1>[a-frxsp\d]+)(, (?P<arg2>[a-frxsp\d]+)(, (?P<arg3>[a-frxsp\d]+))?)?)?$')
re_ldr_str = re.compile(
r'(?P<op>(ldr)|(str)) (?P<reg>[r\d+]+), \[(?P<addr>[a-frxps\d]+)(, (?P<offset>[a-fxr\d]+))?\]$')
re_push_pop = re.compile(
r'(?P<op>(push)|(pop)) \{(?P<args>[a-frxlsp, \d]+)\}$')
re_ldm_stm = re.compile(
r'(?P<op>(ldm)|(stm)) (?P<reg>[r\d+]+)(?P<increment>!)?, \{(?P<args>[a-frxlsp, \d]+)\}$')
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
	# 4 byte aligned pc used for address calculations
	pc = instr['offset']
	R[15] = pc + 4 if pc % 4 == 0 else pc + 2
	op = parseop(instr['opcode'])
	name = op['op']
	args = op['args'] if 'args' in op else None
	if name.startswith('bl') or name in ['b', 'bne']:
		pass # skip branching instructions
	elif name in ['cmp']:
		pass # skip instructions that are currently nops in our coarse model
	elif name in ['ldr', 'str']:
		addr = R[op['addr']]
		if op['offset'] is not None:
			addr += value(op['offset'])
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
	elif name in ['stm', 'ldm']:
		addr = R[r2i(op['reg'])]
		for rr in sorted(r2i(rr) for rr in args):
			if name == 'stm': mem[addr] = R[rr]
			else            : R[rr] = mem[addr]
			addr += 4
		if op['increment'] is not None:
			R[r2i(op['reg'])] = addr
	elif name.startswith('mov'):
		R[args[0]] = value(args[1])
	elif name in ['add', 'adds', 'sub', 'subs', 'lsl', 'lsls']:
		name = name[:-1] if name[-1] == 's' else name
		operation = {
			'add': lambda a,b: a + b,
			'sub': lambda a,b: a - b,
			'lsl': lambda a,b: a << b,
		}[name]
		if len(args) > 2:
			R[args[0]] = operation(value(args[1]), value(args[2]))
		else:
			R[args[0]] = operation(value(args[0]), value(args[1]))
	else:
		print("TODO: handle operation `{}`".format(op['op']))

	print("\033[1m0x{:02x}\033[0m: {} => {}".format(instr['offset'], instr['opcode'], op))
	print(R)





# load and execute instructions
max_instr_count = 30000
instr_count = 0

# initialize registers if set via command line arguments
for reg in sys.argv[3:]:
	mm = re.match(r'(?P<reg>[rsplc\d+]+)=(?P<value>[a-fx\d]+)', reg)
	if mm:
		R[mm.group('reg')] = i2i(mm.group('value'))
	else:
		raise Exception("Invalid register init parameter `{}`. Try e.g. sp=0x123".format(reg))

with open(pc) as ff:
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

mem.print_known_content()

r2.quit()
