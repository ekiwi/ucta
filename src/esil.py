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


# this fixes any bugs that I found in the ESIL emitter of radare2
# these fixes should be contributed back some time, but not today...
from thumb2 import re_ldr_str, re_ldm_stm
import sys
def patch_esil(instr):
	op = instr['opcode']
	# somehow radare2 ignores the post increment flag of ldr/str instructions
	m = re_ldr_str.match(op)
	if m and m.group('post'):
		fix = ',{},{},+='.format(m.group('post'), m.group('addr'))
		return instr['esil'] + fix
	if m and m.group('pre'):
		fix = ',{},{},+='.format(m.group('offset'), m.group('addr'))
		return instr['esil'] + fix
	# sometimes radare2 misses register offset arguments and instead puts a 0 or 0x0
	if m and m.group('offset') and is_reg(m.group('offset')):
		cmds = instr['esil'].split(',')
		if '0' in cmds[:2] or '0x0' in cmds[:2]:
			if cmds[0] in ['0', '0x0']: cmds[0] = m.group('offset')
			if cmds[1] in ['0', '0x0']: cmds[1] = m.group('offset')
			instr['esil'] = ','.join(cmds)
	# the radare2 implementation of stm/ldm seems buggy
	m = re_ldm_stm.match(op)
	if m:
		cmds = []
		dd = m.groupdict()
		args = dd['args'].split(", ")
		for (arg, offset) in zip(args, range(0, len(args)*4, 4)):
			if   dd['op'] == 'stm': cmds.append('{},{},{},+,=[4]'.format(arg, dd['reg'], offset))
			elif dd['op'] == 'ldm': cmds.append('{},{},+,[4],{},='.format(dd['reg'], offset, arg))
			else: raise Exception('unhandled op code `{}`'.format(dd['op']))
		if dd['increment'] is not None:
			cmds.append('{},{},+='.format(4 * len(args), dd['reg']))
		return ','.join(cmds)
	return instr['esil']

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
	def __init__(self, mem, regs, analysis):
		self.mem = mem
		self.R = regs
		self.analysis = analysis
		self.esil_commands = {
			'$$': lambda t,stack: stack.append(self.R['pc']),
			'=' : lambda t,stack: self.store_to_reg(stack.pop(), stack),
		}
		self.add_commands(self.compare, ['==','<','<=','>','>='])
		self.bin_op_tokens = ['<<','>>','<<<','>>>','&','|','^','+','-','*','/','%']
		self.add_commands(self.bin_op, self.bin_op_tokens)
		self.add_commands(self.unary_op, ['!', '++', '--'])
		self.add_commands(self.reg_op, ['+=','-=','*=','/=','%=','<<=','>>=','&=','|=','^=','++=','--=','!='])
		self.add_commands(self.store, ['=[' + t + ']' for t in ['', '1', '2', '4', '8']])
		self.add_commands(self.store_multiple, ['=[*]'])
		self.add_commands(self.load,  [ '[' + t + ']' for t in ['', '1', '2', '4', '8']])
		self.add_commands(self.load_multiple, ['[*]'])
		self.add_commands(self.not_implemented_yet,
			['TRAP', '$', 'SWAP', 'PICK', 'RPICK', 'DUP', 'NUM', 'CLEAR', 'BREAK', 'GOTO', 'TODO'])

	def add_commands(self, cmd, tokens):
		for tok in tokens:
			self.esil_commands[tok] = cmd

	def exec(self, instr):
		esil = patch_esil(instr)
		self.R[15] = (instr['offset'], {'src': 'pc'})
		if instr['type'] in ['cjmp', 'cmp']:
			return # unsupported instructions
		stack = []
		#print(esil)
		for token in esil.split(','):
			#print(stack)
			if token in self.esil_commands:
				self.esil_commands[token](token, stack)
			else:
				stack.append((token, {'src': 'literal'}))

	def pop(self, stack):
		(value, meta) = stack.pop()
		if meta['src'] == 'literal':
			if isinstance(value, int): return (value, meta)
			elif is_reg(value):
				vv = self.R[value]
				self.analysis.on_load_from_reg(vv, reg=value)
				return vv
			else:
				return (int(value, 0), meta)
		else:
			return (value, meta)

	def compare(self, token, stack):
		op = {
			'==': lambda a,b: a == b,
			'<':  lambda a,b: a < b,
			'<=': lambda a,b: a <= b,
			'>':  lambda a,b: a > b,
			'>=': lambda a,b: a >= b,
		}
		(a,b) = (self.pop(stack), self.pop(stack))
		c = (int(op[token](a[0],b[0])), {'src': token})
		self.analysis.on_compare(a,b,c)
		stack.append(c)

	def bin_op(self, token, stack):
		ws = WordSize
		op = {
			'<<' : lambda a,b: a << b,
			'>>' : lambda a,b: a >> b,	# TODO: arithmetic or logic?
			'<<<': lambda a,b: (a << b) | (a >> (ws - b)),
			'>>>': lambda a,b: (a >> b) | (a << (ws - b)),
			'&'  : lambda a,b: a & b,
			'|'  : lambda a,b: a | b,
			'^'  : lambda a,b: a ^ b,
			'+'  : lambda a,b: a + b,
			'-'  : lambda a,b: a - b,
			'*'  : lambda a,b: a * b,
			'/'  : lambda a,b: a / b,
			'%'  : lambda a,b: a % b,
		}
		(a,b) = (self.pop(stack), self.pop(stack))
		c = (int(op[token](a[0], b[0])) & WordMax, {'src': token})
		self.analysis.on_binary_op(a,b,c)
		stack.append(c)

	def unary_op(self, token, stack):
		op = {
			'!' : lambda a: int(not bool(a)),
			'++': lambda a: a + 1,
			'--': lambda a: a - 1,
		}
		a = self.pop(stack)
		c = (op[token](a[0]) & WordMax, {'src': token})
		self.analysis.on_unary_op(a,c)
		stack.append(c)

	def reg_op(self, token, stack):
		# peek register name as it will be consumed by the op
		reg = stack[-1]
		op = token[:-1]
		if op in self.bin_op_tokens: self.bin_op(op, stack)
		else                       : self.unary_op(op, stack)
		self.store_to_reg(reg, stack)

	def store_to_reg(self, reg, stack):
		a = self.pop(stack)
		self.analysis.on_store_to_reg(a, reg)
		self.R[reg[0]] = a

	def load(self, token, stack):
		bytes = token[1:-1]
		addr = self.pop(stack)
		c = self.mem.read(addr[0], size=int(bytes))
		self.analysis.on_load(addr, c)
		stack.append(c)

	def store(self, token, stack):
		bytes = token[2:-1]
		addr = self.pop(stack)
		value = self.pop(stack)
		self.mem.write(addr[0], value, size=int(bytes))
		self.analysis.on_store(addr, value=value)

	def load_multiple(self, token, stack):
		# from radare2 (`libr/anal/p/anal_arm_cs.s`):
		# POP { r4,r5, r6}
		# r4,r5,r6,3,sp,[*],12,sp,+=
		addr = self.pop(stack)
		count = self.pop(stack)[0]
		regs = [stack.pop() for ii in range(0,count)]
		for reg in regs:
			value = self.mem.read(addr[0], size=4)
			self.analysis.on_load(addr, value=value)
			self.R[reg[0]] = value
			self.analysis.on_store_to_reg(value, reg)
			addr = (addr[0] + 4, addr[1])

	def store_multiple(self, token, stack):
		# from radare2 (`libr/anal/p/anal_arm_cs.s`):
		# PUSH { r4, r5, r6, r7, lr }
		# 4,sp,-=,lr,sp,=[4],
		# 4,sp,-=,r7,sp,=[4],
		# 4,sp,-=,r6,sp,=[4],
		# 4,sp,-=,r5,sp,=[4],
		# 4,sp,-=,r4,sp,=[4]
		# 20,sp,-=,r4,r5,r6,r7,lr,5,sp,=[*]
		addr = self.pop(stack)
		count = self.pop(stack)[0]
		regs = [stack.pop() for ii in range(0,count)]
		for reg in regs:
			value = self.R[reg[0]]
			self.analysis.on_load_from_reg(value, reg)
			self.mem.write(addr[0], value, size=4)
			self.analysis.on_store(addr, value=value)
			addr = (addr[0] + 4, addr[1])

	def not_implemented_yet(self, token, stack):
		raise Exception("Esil instruction `{}` has not been implemented yet!".format(token))
