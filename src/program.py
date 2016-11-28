#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This file contains the database interface to the program facts.

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

import r2pipe

class Program:
	""" DB that can be queried for program facts
	"""
	def __init__(self, fw_elf):
		self.filename = fw_elf
		self.r2 = r2pipe.open(self.filename)
		# enable esil output
		self.r2.cmd("e asm.esil = true")
	def read_instruction(self, addr):
		return self.r2.cmdj("pdj 1 @ 0x{:08x}".format(addr))[0]
	def read_rom(self, addr, bytes):
		length = {1:'b', 2:'w',4:'x',8:'q'}[bytes]
		return int(self.r2.cmd("pfv {} @ 0x{:08x}".format(length, addr)), 16)
	def close(self):
		self.r2.quit()
