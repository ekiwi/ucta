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

(This is
"""


class EsilExecution:
	def __init__(self, mem, regs):
		self.mem = mem
		self.R = regs

	def exec(self, instr):
		print(instr)


class EsilParser:
	""" tries to emmit simple three address code from ESIL, let's see how far we get with that
	"""
	def __init__(self):
		pass

	def parse(self, cmd_str):
		stack = []
		for cmd in cmd_str.split(','):


class BinaryOp:
	def __init__(self, a, b, op):
		self.a = a
		self.b = b
		self.op = op
	def __eq__(self, other):
		if op in ['+', '*']:
			return ((self.a == other.a and self.b == other.b) or
			        (self.a == other.b and self.b == other.a))
			       and self.op = other.op
		else:
			return self.a == other.a and self.b == other.b and self.op = other.op

class Assign:
	def __init__(self, lvalue, rvalue):
		self.lvalue = lvalue
		self.rvalue = rvalue
	def __eq__(self, other):
		return self.lvalue == other.lvalue and self.rvalue = other.rvalue

class Register:
	def __init__(self, name):
		# TODO: normalize name
		self.name = name
	def __eq__(self, other):
		return self.name == other.name

if __name__ == '__main__':
	import unittest
	class Test(unittest.TestCase):
		def setUp(self):
			self.parser = EsilParser()
			self.parse = self.parser.parse
		def test_single_statements(self):
			# examples from the `buggy_function` from overflow00
			# sub sp, 0xc
			self.assertEqual(
				self.parse('12,sp,-='),
				Assign(Register('sp'), BinaryOp('sp', 12, '-')))
			#
			self.assertEqual(
				self.parse('12,sp,-='),
				Assign(Register('sp'), BinaryOp('sp', 12, '-')))
