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

return_addr_locs = []

def on_store(addr, value, src_reg, pc, instr_count):
	if addr in return_addr_locs:
		raise Exception("Return address overwriten with 0x{:08x} @ pc=0x{:08x}".format(value, pc))
	elif src_reg == 14:
		return_addr_locs.append(addr)

def on_load(addr, value, dst_reg, pc, instr_count):
	if addr in return_addr_locs:
		return_addr_locs.remove(addr)
