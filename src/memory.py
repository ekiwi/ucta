#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This file contains the concrete and symbolic memory implementation for ucta

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

import shutil
from enum import Enum
from thumb2 import r2i # TODO: move to common file

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
	def __init__(self, count=16):
		self.name = 'regs'
		self.data = [0] * count
		self.state = [MemState.unknown] * count
	def __getitem__(self, ii):
		ii = r2i(ii)
		if self.state[ii] == MemState.unknown:
			raise Exception("Cannot read from r{}: value unknown".format(ii))
		return self.data[ii]
	def __setitem__(self, ii, vv):
		self.state[r2i(ii)] = MemState.concrete
		self.data[r2i(ii)] = vv
	def __str__(self):
		cols = int(shutil.get_terminal_size((80, 20)).columns / len(self.data))
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
		self.print_mem = False
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
		if self.print_mem:
			print("0x{:08x} => 0x{:08x}".format(addr, vv))
		return vv
	def write_bytes(self, addr, bytes, vv):
		for offset in range(0, bytes):
			self.write(addr + offset, (vv >> (8 * offset)) & 0xff)
		if self.print_mem:
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
	def __init__(self, name, start, bytes, prog):
		super().__init__(name, start, bytes)
		self.prog = prog
	def read(self, addr):
		return self.prog.read_rom(addr, 1)
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
		try:
			sec = next(sec for sec in self.sections if sec.addr_in_range(transaction))
			return sec.commit(transaction)
		except:
			raise Exception("Cannot access memory at: 0x{:08x}".format(transaction.addr))
	# convenience methods to create and execute transactions
	def read(self, addr, size='w'):
		bytes = size if isinstance(size, int) else {'w':4,'h':2,'b':1}[size]
		return self.commit(MemoryRead(addr=addr, bytes=bytes))
	def write(self, addr, value, size='w'):
		bytes = size if isinstance(size, int) else {'w':4,'h':2,'b':1}[size]
		return self.commit(MemoryWrite(addr=addr, bytes=bytes, value=value))

	def print_known_content(self):
		for sec in self.sections:
			if isinstance(sec, Ram): sec.print_known_content()
