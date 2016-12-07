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
	def __init__(self, instr_count, instr, sp):
		self.instr_count = instr_count
		self.instr = instr
		self.sp = sp
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


class FunctionTracker(AnalysisTool):
	def __init__(self):
		from dwarf import load_fake_dwarf
		self.functions = load_fake_dwarf()
		self.fun_stack = []
		self.frame_ptr = []
		self.print = lambda x: None
		#self.print = print
	def get_function(self, pc):
		for ff in self.functions:
			if pc >= ff['lowpc'] and pc < ff['highpc']:
				return ff
		return {'name': 'unknown'}
	def next_step(self, step):
		super(FunctionTracker, self).next_step(step)
		# track new functions to calculate frame pointer
		fun = self.get_function(step.pc)
		if len(self.fun_stack) == 0 or fun != self.fun_stack[-1]:
			# this does not handle recursive functions
			if len(self.fun_stack) > 1 and fun == self.fun_stack[-2]:
				self.print("{} <= {}".format(self.fun_stack[-2]['name'], self.fun_stack[-1]['name']))
				self.fun_stack.pop()
				self.frame_ptr.pop()
			else:
				if len(self.fun_stack) > 0:
					self.print("{} => {}".format(self.fun_stack[-1]['name'], fun['name']))
				else:
					self.print("=> {}".format(fun['name']))
				self.fun_stack.append(fun)
				self.frame_ptr.append(step.sp[0])

# currently only supports pointers to stack allocated fixed size arrays
class PointerTracker(FunctionTracker):
	def __init__(self):
		super().__init__()
	def find_stack_array(self, addr):
		for var in self.fun_stack[-1]['vars']:
			if var['location']['mem'] != 'stack': continue
			if var['type']['name'] != 'array': continue
			start = self.frame_ptr[-1] + var['location']['offset']
			if start == addr:
				end = start + var['type']['length'] * var['type']['base']['bytes']
				step = var['type']['base']['bytes']
				return {'name': var['name'], 'start': start, 'end': end, 'step': step}
		return None
	def on_store_to_reg(self, value, reg):
		if len(self.fun_stack) == 0:
			return
		if reg[0] == 'sp':
			value[1]['array'] = []
			return
		if not 'regs' in value[1]:
			return
		if 'sp' in value[1]['regs']:
			if 'array' in value[1] and len(value[1]['array']) > 0: return
			a = self.find_stack_array(value[0])
			if a is not None:
				value[1]['array'] = [a]
	def on_store(self, addr, value):
		self.on_memory_access(addr, value, self.on_store_array)
	def on_load(self, addr, value):
		self.on_memory_access(addr, value, self.on_load_array)
	def on_memory_access(self, addr, value, on_access_array):
		if 'array' in addr[1] and len(addr[1]['array']) > 0:
			assert(len(addr[1]['array']) == 1)
			array = addr[1]['array'][0]
			index = (addr[0] - array['start']) / array['step']
			assert(index.is_integer())
			on_access_array(array, int(index), addr, value)
	def on_binary_op(self, a, b, result):
		a_array = a[1]['array'] if 'array' in a[1] else []
		b_array = b[1]['array'] if 'array' in b[1] else []
		result[1]['array'] = a_array + b_array
	def on_unary_op(self, a, result):
		if 'array' in a[1]:
			result[1]['array'] = a[1]['result']
	def on_store_array(self, array, index, addr, value):
		pass
	def on_load_array(self, array, index, addr, value):
		pass

class ArrayBoundsChecker(PointerTracker):
	def __init__(self):
		super().__init__()
	def on_store_array(self, array, index, addr, value):
		print('{}[{}] <= {}'.format(array['name'], index, value[0]))
		if addr[0] < array['start'] or addr[0] >= array['end']:
			print("addr:  {}".format(addr))
			print("value: {}".format(value))
			raise Exception("ERROR")
	def on_load_array(self, array, index, addr, value):
		print('{}[{}] => {}'.format(array['name'], index, value[0]))
		if addr[0] < array['start'] or addr[0] >= array['end']:
			print("addr:  {}".format(addr))
			print("value: {}".format(value))
			raise Exception("ERROR")


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
