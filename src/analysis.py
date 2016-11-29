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
	def on_store(self, addr, value, src_reg):
		for tool in self.tools: tool.on_store(addr, value, src_reg)
	def on_load(self, addr, value, dst_reg):
		for tool in self.tools: tool.on_load(addr, value, dst_reg)

class AnalysisTool:
	def __init__(self):
		self.step = SimulationStep.default()
	def next_step(self, step):
		self.step = step
	def on_store(self, addr, value, src_reg):
		pass
	def on_load(self, addr, value, dst_reg):
		pass


class ReturnAddressOverwriteCheck(AnalysisTool):
	def __init__(self):
		self.return_addr_locs = {}
	def on_store(self, addr, value, src_reg):
		if addr in self.return_addr_locs:
			msg  = "Return address overwriten with 0x{:08x} @ pc=0x{:08x}".format(value, self.step.instr['offset'])
			ii = self.return_addr_locs[addr]
			msg += "; originally saved at instr_count={} pc=0x{:08x}".format(ii.instr_count, ii.instr['offset'])
			raise Exception(msg)
		elif src_reg == 14:
			self.return_addr_locs[addr] = self.step
	def on_load(self, addr, value, dst_reg):
		if addr in self.return_addr_locs:
			del self.return_addr_locs[addr]
