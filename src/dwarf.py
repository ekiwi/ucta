#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This file contains code to extract DWARF debug information from the elf file.

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

import sys
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class

def parse_function(range_lists, die):
	#print(die.attributes)
	fun = {}
	try:
		fun['lowpc']  = die.attributes['DW_AT_low_pc'].value
		fun['highpc'] = die.attributes['DW_AT_high_pc'].value
		fun['name'] = die.attributes['DW_AT_name'].value
		fun['file'] = die.attributes['DW_AT_decl_file'].value
		fun['line'] = die.attributes['DW_AT_decl_line'].value
	except KeyError:
		return None
	print(describe_form_class(die.attributes['DW_AT_decl_file'].form))
	if 'DW_AT_MIPS_linkage_name' in die.attributes:
		fun['cxx_name'] = die.attributes['DW_AT_MIPS_linkage_name'].value
	print(fun)

	# search for parameters and variables
	fun['params'] = []
	fun['vars'] = []
	for cc in die.iter_children():
		if cc.tag == 'DW_TAG_formal_parameter':
			param = parse_var(range_lists, cc)
			if param is not None: fun['params'].append(param)
		elif cc.tag == 'DW_TAG_variable':
			var = parse_var(range_lists, cc)
			if var is not None: fun['vars'].append(var)

	print('params: {}'.format(fun['params']))
	print('vars:   {}'.format(fun['vars']))

	""" Trying to extract information about the frame size leads to
	    an exception in pyelftools....
	if die.attributes['DW_AT_frame_base'].form in ['DW_FORM_data4']:
		offset = die.attributes['DW_AT_frame_base'].value
		print('fram_base.offset=0x{:x}'.format(offset))
		frame_base = range_lists.get_range_list_at_offset(offset)
		print(frame_base)
	"""
	return fun

def parse_var(range_lists, die):
	var = { 'name': die.attributes['DW_AT_name'].value }
	print(var['name'])
	print(die.attributes['DW_AT_location'])
	print(die.attributes['DW_AT_type'])
	return var




################################################################################
# Fake DWARF for demo!
################################################################################
# this only contains data that can be found in `traces/overflow00/target.elf`
# however, we do not have a good automated way of loading this data directly
# from the file yet

def load_fake_dwarf():
	int_t = {'name': 'int', 'bytes': 4}
	uint8_t = {'name': 'uint8_t', 'bytes': 1}
	unsigned_char_t = {'name': 'unsigned char', 'bytes': 1 }
	void_ptr_t = {'name': 'pointer', 'bytes': 4 }
	size_t = {'name': 'size_t', 'bytes': 4 }

	return [
		{ 'name': 'main',
		  'file': '/home/kevin/d/ucta/program_under_test/main.cpp', 'line': 26,
		  'lowpc': 0x080001f4, 'highpc': 0x08000288,
		  'return': int_t,
		  'params': [],
		  'vars': [
		    { 'name': 'good_inp', 'location': {'mem': 'stack', 'offset': -28}, # offset: 0x1c
		      'type': {'name': 'array', 'length': 8+1,
		               'base': unsigned_char_t } },
		    { 'name': 'bad_inp', 'location': {'mem': 'stack', 'offset': -48}, # offset: 0x30
		      'type': {'name': 'array', 'length': 16+1,
		               'base': unsigned_char_t } },
		  ]
		},
		{ 'name': 'buggy_function',
		  'file': '/home/kevin/d/ucta/program_under_test/main.cpp', 'line': 3,
		  'lowpc': 0x080001a0, 'highpc': 0x080001c8,
		  'return': uint8_t,
		  'params': [
		    { 'name': 'packet', 'location': {'mem': 'reg0'},
		      'type': {'name': 'array', 'length': 8, 'base': uint8_t } },
		  ],
		  'vars': [
		    { 'name': 'buffer', 'location': {'mem': 'stack', 'offset': -16},
		      'type': {'name': 'array', 'length': 8,
		               'base': unsigned_char_t } },
		    # we only care about arrays right now...
		  ]
		},
		{ 'name': 'memcpy',
		  'file': '/builddir/build/BUILD/newlib-2.2.0-1/newlib/libc/include/string.h', 'line': 17,
		  'lowpc': 0x08000608, 'highpc': 0x0800061e,
		  'return': uint8_t,
		  'params': [
		    { 'name': 'dst0', 'location': {'mem': 'reg0'}, 'type': void_ptr_t },
		    { 'name': 'src0', 'location': {'mem': 'reg1'}, 'type': void_ptr_t },
		    { 'name': 'len0', 'location': {'mem': 'reg2'}, 'type': size_t },
		  ],
		  'vars': [
		    # TODO
		  ]
		},
	]

if __name__ == '__main__':
	filename = sys.argv[1]
	ff = open(filename, 'rb')
	elffile = ELFFile(ff)
	dwinfo = elffile.get_dwarf_info()
	range_lists = dwinfo.range_lists()

	print(load_fake_dwarf())

	# find all functions
	count = 0

	for cu in dwinfo.iter_CUs():
		# iterate over top level functions
		for die in cu.get_top_DIE().iter_children():
			if die.tag == 'DW_TAG_subprogram':
				fun = parse_function(range_lists, die)
				if fun is not None: count += 1
				if count > 6: sys.exit(0)
	#print("found {} functions".format(count))

	ff.close()
