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


WordMax = (1<<32) - 1

# load firmware image
r2 = r2pipe.open(fw)	# TODO: ugly global


class MemoryTransaction:
	def __init__(self, addr, bytes):
		self.addr = addr
		self.bytes = bytes	# this is the "byte count" ... needs a better short name
class MemoryRead(MemoryTransaction):
	def __init__(self, addr, bytes):
		super().__init__(addr, bytes)
class MemoryWrite(MemoryTransaction):
	def __init__(self, addr, bytes, value):
		super().__init__(addr, bytes)
		self.value = value


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
			if isinstance(self.data[ii], int):
				out += 'r{}: 0x{:08x}   '.format(ii, self.data[ii])
			else:
				out += 'r{}: {}   '.format(ii, self.data[ii])
			cc += 1
		return out

class MemoryBase:
	def __init__(self, name, start, bytes):
		self.name = name
		self.start = start
		self.bytes = bytes
	def addr_in_range(self, transaction):
		return (transaction.addr                     >= self.start and
		        transaction.addr + transaction.bytes <= self.start + self.bytes)
	def commit(self, transaction):
		addr = transaction.addr
		if isinstance(transaction, MemoryRead):
			return self.read_bytes(addr, transaction.bytes)
		elif isinstance(transaction, MemoryWrite):
			return self.write_bytes(addr, transaction.bytes, transaction.value)
	def read_bytes(self, addr, bytes):
		vv = 0
		for offset in range(0, bytes):
			vv |= self.read(addr + offset) << (8 * offset)
		print("0x{:08x} => 0x{:08x}".format(addr, vv))
		return vv
	def write_bytes(self, addr, bytes, vv):
		for offset in range(0, bytes):
			self.write(addr + offset, (vv >> (8 * offset)) & 0xff)
		print("0x{:08x} <= 0x{:08x}".format(addr, vv))
	def read(self, addr):
		raise Exception("Read method to retrive bytes needs to be implemented!")
	def write(self, addr, vv):
		raise Exception("Write method to store bytes needs to be implemented!")


class Ram(MemoryBase):
	def __init__(self, name, start, bytes):
		super().__init__(name, start, bytes)
		self.data = [0] * self.bytes
		self.state = [MemState.unknown] * self.bytes
	def read(self, addr):
		ii = addr - self.start
		if self.state[ii] == MemState.unknown:
			raise Exception("Cannot read from addr 0x{:08x}: value unknown".format(addr))
		return self.data[ii]
	def write(self, addr, vv):
		ii = addr - self.start
		self.data[ii]  = vv
		self.state[ii] = MemState.concrete
	def print_known_content(self):
		for word in range(0, len(self.data) >> 2):
			byte_range = range(word * 4, word * 4 + 4)
			if all(self.state[ii] == MemState.unknown for ii in byte_range):
				continue
			out = '0x{:08x}: 0x'.format(word * 4 + self.start)
			for ii in reversed(byte_range):
				if self.state[ii] == MemState.unknown: out += '??'
				else: out += '{:02x}'.format(self.data[ii])
			print(out + '   ')

class Rom(MemoryBase):
	def __init__(self, name, start, bytes):
		super().__init__(name, start, bytes)
	def read(self, addr):
		return int(r2.cmd("pfv b @ 0x{:08x}".format(addr)), 16)
	def write(self, addr, vv):
		raise Exception('Cannot write to Read Only Memory.')

class SymVar:
	def __init__(self, src):
		self.src = src
	def __str__(self): return self.src

class PeripheralMemory(Ram):
	def __init__(self, name, start, bytes):
		super().__init__(name, start, bytes)
	def read(self, addr):
		# TODO: remember that memory location was read
		# return SymVar("{} @ 0x{:08x}".format(self.name, addr))
		# TODO: distinguish between symbolic variables and concrete variables
		#       for now we just always return 0 and hope that the value is never
		#       used for anything important
		return 0
	def write(self, addr, vv):
		# TODO: remember that memory location was written
		ii = addr - self.start
		self.data[ii]  = vv

class Memory:
	def __init__(self, *sections):
		self.sections = sections
	def commit(self, transaction):
		assert(isinstance(transaction, MemoryTransaction))
		sec = next(sec for sec in self.sections if sec.addr_in_range(transaction))
		return sec.commit(transaction)
		# TODO: handle cases in which no section is found
	# convenience methods to create and execute transactions
	def read(self, addr, size='w'):
		return self.commit(MemoryRead(addr=addr, bytes={'w':4,'h':2,'b':1}[size]))
	def write(self, addr, value, size='w'):
		return self.commit(MemoryWrite(addr=addr, bytes={'w':4,'h':2,'b':1}[size], value=value))

	def print_known_content(self):
		for sec in self.sections:
			if isinstance(sec, Ram): sec.print_known_content()


mem = Memory(
	Rom('flash',  bytes=1024 * 1024, start=0x08000000),
	Ram('ccm',    bytes=  64 * 1024, start=0x10000000),
	Ram('sram1',  bytes= 112 * 1024, start=0x20000000),
	Ram('sram2',  bytes=  16 * 1024, start=0x2001C000),
	Ram('backup', bytes=   4 * 1024, start=0x40024000),
	PeripheralMemory('apb1', bytes=  0x7fff, start=0x40000000),
	PeripheralMemory('apb2', bytes=  0x57ff, start=0x40010000),
	PeripheralMemory('ahb1', bytes= 0x5ffff, start=0x40020000),
	PeripheralMemory('ahb2', bytes= 0x60bff, start=0x50000000))

R = RegisterBank()

# parse opcode strings
re_reg_arg = re.compile(	# parses opcodes with up to 3 arguments
r'(?P<op>[a-z]+) ((?P<arg1>[a-flrxsp\d]+)(, (?P<arg2>[a-frxsp\d]+)(, (?P<arg3>[a-frxsp\d]+))?)?)?$')
re_ldr_str = re.compile(
r'(?P<op>(ldr)|(strh?b?)) (?P<reg>[r\d+]+), \[(?P<addr>[a-frxps\d]+)(, (?P<offset>[a-fxr\d]+))?\]$')
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
	elif name in ['ldr', 'str', 'strh', 'strb']:
		size = 'w' if name[-1] == 'r' else name[-1]
		addr = R[op['addr']]
		if op['offset'] is not None:
			addr += value(op['offset'])
		if name == 'ldr':
			R[op['reg']] = mem.read(addr, size)
		else:
			mem.write(addr, R[op['reg']], size)
	elif name == 'push':
		for rr in sorted((r2i(rr) for rr in args), reverse=True):
			mem.write(R[r2i('sp')], R[rr])
			R[r2i('sp')] = R[r2i('sp')] - 4
	elif name == 'pop':
		for rr in sorted(r2i(rr) for rr in args):
			R[r2i('sp')] = R[r2i('sp')] + 4
			R[rr] = mem.read(R[r2i('sp')])
	elif name in ['stm', 'ldm']:
		addr = R[r2i(op['reg'])]
		for rr in sorted(r2i(rr) for rr in args):
			if name == 'stm': mem.write(addr, R[rr])
			else            : R[rr] = mem.read(addr)
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
			R[args[0]] = operation(value(args[1]), value(args[2])) & WordMax
		else:
			R[args[0]] = operation(value(args[0]), value(args[1])) & WordMax
	else:
		print("\033[31mTODO\033[0m: handle operation `{}`".format(op['op']))

	print(R)





# load and execute instructions
max_instr_count = 30000
instr_count = 0

# initialize registers if set via command line arguments
load_sp_from_rom = True
for reg in sys.argv[3:]:
	mm = re.match(r'(?P<reg>[rsplc\d+]+)=(?P<value>[a-fx\d]+)', reg)
	if mm:
		R[mm.group('reg')] = i2i(mm.group('value'))
		if mm.group('reg') == 13: load_sp_from_rom = False
	else:
		raise Exception("Invalid register init parameter `{}`. Try e.g. sp=0x123".format(reg))
if load_sp_from_rom:
	R['sp'] = mem.read(0x08000000)

with open(pc) as ff:
	for line in ff.readlines():
		if not line.startswith('PC '):
			print("Unknown line: {}".format(line))
			continue
		addr = line[3:].strip()
		instr = r2.cmdj("pdj 1 @ {}".format(addr))[0]
		print("\033[1m0x{:02x}\033[0m: {} => {}".format(instr['offset'], instr['opcode'], parseop(instr['opcode'])))
		exec(instr)
		instr_count += 1
		if instr_count >= max_instr_count:
			break

mem.print_known_content()

r2.quit()
