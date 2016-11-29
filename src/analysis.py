#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This file contains some analysis plugins for ucta.

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


class SimulationStep:
	def __init__(self, instr_count, instr):
		self.instr_count = instr_count
		self.instr = instr
	@property
	def pc(self): return self.instr['offset']
	@staticmethod
	def default():
		return SimulationStep(instr_count=-1, instr={'offset':-1, 'opcode':'', 'esil':''})

class AnalysisTools:
	def __init__(self, *tools):
		self.tools = tools
	def next_step(self, step):
		for tool in self.tools: tool.next_step(step)
	def on_store(self, addr, value):
		for tool in self.tools: tool.on_store(addr, value)
	def on_load(self, addr, value):
		for tool in self.tools: tool.on_load(addr, value)
	def on_assign_reg(self, reg, value):
		for tool in self.tools: tool.on_assign_reg(reg, value)
	def on_compare(self, a, b, result):
		for tool in self.tools: tool.on_compare(a, b, result)
	def on_binary_op(self, a, b, result):
		for tool in self.tools: tool.on_binary_op(a, b, result)
	def on_unary_op(self, a, result):
		for tool in self.tools: tool.on_unary_op(a, result)
	def on_load_from_reg(self, value, reg):
		for tool in self.tools: tool.on_load_from_reg(value, reg)
	def on_store_to_reg(self, value, reg):
		for tool in self.tools: tool.on_store_to_reg(value, reg)

class AnalysisTool:
	def __init__(self):
		self.step = SimulationStep.default()
	def next_step(self, step):
		self.step = step
	def on_store(self, addr, value):
		pass
	def on_load(self, addr, value):
		pass
	def on_assign_reg(self, reg, value):
		pass
	def on_compare(self, a, b, result):
		pass
	def on_binary_op(self, a, b, result):
		pass
	def on_unary_op(self, a, result):
		pass
	def on_load_from_reg(self, value, reg):
		pass
	def on_store_to_reg(self, value, reg):
		pass

class ReturnAddressOverwriteCheck(AnalysisTool):
	def __init__(self):
		self.return_addr_locs = {}
	def on_store(self, addr, value):
		if addr[0] in self.return_addr_locs:
			msg  = "Return address overwriten with 0x{:08x} @ pc=0x{:08x}".format(value[0], self.step.instr['offset'])
			ii = self.return_addr_locs[addr[0]]
			msg += "; originally saved at instr_count={} pc=0x{:08x}".format(ii.instr_count, ii.instr['offset'])
			raise Exception(msg)
		elif 'lr' in value[1]['regs']:
			self.return_addr_locs[addr[0]] = self.step
	def on_load(self, addr, value):
		if addr[0] in self.return_addr_locs:
			del self.return_addr_locs[addr[0]]

class RegisterTainter(AnalysisTool):
	def __init__(self):
		self.return_addr_locs = {}
	def on_load(self, addr, value):
		value[1]['regs'] = []
	def on_load_from_reg(self, value, reg):
		if isinstance(reg, tuple):
			reg = reg[0]
		value[1]['regs'] = [reg]
	def on_binary_op(self, a, b, result):
		a_regs = a[1]['regs'] if 'regs' in a[1] else []
		b_regs = b[1]['regs'] if 'regs' in b[1] else []
		result[1]['regs'] = a_regs + b_regs
