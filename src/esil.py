#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This file contains the radare2 esil execution engine.

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
ESIL documentation:
https://radare.gitbooks.io/radare2book/content/esil.html

"""

import re

WordSize = 32
WordMax  = (1 << WordSize) - 1


# register to index
def r2i(name):
	if isinstance(name, int):
		return name
	elif re.match(r'r(\d)|(1\d)$', name):
		return int(name[1:])
	else:
		return {'ip':12, 'sp': 13, 'lr': 14, 'pc': 15}[name]

def is_reg(name):
	return re.match(r'((r((\d)|(1\d)))|(sp)|(lr)|(pc)|(ip))$', name) is not None

class EsilExecution:
	def __init__(self, mem, regs):
		self.mem = mem
		self.R = regs
		self.esil_commands = {
			'$$': lambda t,stack: stack.append(self.R['pc']),
			'=' : lambda t,stack: self.save_to_reg(stack.pop(), stack),
		}
		self.add_commands(self.compare, ['==','<','<=','>','>='])
		self.bin_op_tokens = ['<<','>>','<<<','>>>','&','^','+','-','*','/','%']
		self.add_commands(self.bin_op, self.bin_op_tokens)
		self.add_commands(self.unary_op, ['!', '++', '--'])
		self.add_commands(self.reg_op, ['+=','-=','*=','/=','%=','<<=','>>=','&=','^=','++=','--=','!='])
		self.add_commands(self.store, ['=[' + t + ']' for t in ['', '*', '1', '2', '4', '8']])
		self.add_commands(self.load,  [ '[' + t + ']' for t in ['', '*', '1', '2', '4', '8']])
		self.add_commands(self.not_implemented_yet,
			['TRAP', '$', 'SWAP', 'PICK', 'RPICK', 'DUP', 'NUM', 'CLEAR', 'BREAK', 'GOTO', 'TODO'])

	def add_commands(self, cmd, tokens):
		for tok in tokens:
			self.esil_commands[tok] = cmd

	def exec(self, instr):
		self.R[15] = instr['offset']
		if instr['type'] in ['cjmp']:
			return # unsupported instructions
		stack = []
		print(instr['esil'])
		for token in instr['esil'].split(','):
			if token in self.esil_commands:
				self.esil_commands[token](token, stack)
			else:
				stack.append(token)

	def value(self, arg):
		if   isinstance(arg, int): return arg
		elif is_reg(arg)         : return self.R[arg]
		else                     : return int(arg, 0)

	def compare(self, token, stack):
		op = {
			'==': lambda a,b: a == b,
			'<':  lambda a,b: a < b,
			'<=': lambda a,b: a <= b,
			'>':  lambda a,b: a > b,
			'>=': lambda a,b: a >= b,
		}
		(a,b) = (self.value(stack.pop()), self.value(stack.pop()))
		c = int(op[token](a,b))
		stack.append(c)

	def bin_op(self, token, stack):
		ws = WordSize
		op = {
			'<<' : lambda a,b: a << b,
			'>>' : lambda a,b: a >> b,	# TODO: arithmetic or logic?
			'<<<': lambda a,b: (a << b) | (a >> (ws - b)),
			'>>>': lambda a,b: (a >> b) | (a << (ws - b)),
			'&'  : lambda a,b: a & b,
			'^'  : lambda a,b: a ^ b,
			'+'  : lambda a,b: a + b,
			'-'  : lambda a,b: a - b,
			'*'  : lambda a,b: a * b,
			'/'  : lambda a,b: a / b,
			'%'  : lambda a,b: a % b,
		}
		(a,b) = (self.value(stack.pop()), self.value(stack.pop()))
		c = op[token](a,b) & WordMax
		stack.append(c)

	def unary_op(self, token, stack):
		op = {
			'!' : lambda a: int(not bool(a)),
			'++': lambda a: a + 1,
			'--': lambda a: a - 1,
		}
		a = self.value(stack.pop())
		c = op[token](a) & WordMax
		stack.append(c)

	def reg_op(self, token, stack):
		# peek register name as it will be consumed by the op
		reg = stack[-1]
		op = token[:-1]
		if op in self.bin_op_tokens: self.bin_op(op, stack)
		else                       : self.unary_op(op, stack)
		self.save_to_reg(reg, stack)

	def save_to_reg(self, reg, stack):
		self.R[reg] = self.value(stack.pop())

	def load(self, token, stack):
		bytes = token[1:-1]
		addr = self.value(stack.pop())
		if bytes == '*':
			bytes = stack.pop()
		c = self.mem.read(addr, size=int(bytes))
		stack.append(c)

	def store(self, token, stack):
		bytes = token[2:-1]
		addr = self.value(stack.pop())
		if bytes == '*':
			bytes = stack.pop()
		value = self.value(stack.pop())
		self.mem.write(addr, value, size=int(bytes))

	def not_implemented_yet(self, token, stack):
		raise Exception("Esil instruction `{}` has not been implemented yet!".format(token))
