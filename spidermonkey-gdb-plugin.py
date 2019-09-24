#
# Custom GDB commands for debugging mozilla spidermonkey
#
# 2019 @ Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
#

import gdb

# change it for your needs.. :))
__js_debug__ = False

# linux x86-64
jsval_tag_max_double = 0x1fff0

js_value_tag = {
	'double': ['double', jsval_tag_max_double | 0x00],
	'int32': ['32-bit integer', jsval_tag_max_double | 0x01],
	'boolean': ['boolean', jsval_tag_max_double | 0x02],
	'undefined': ['undefined', jsval_tag_max_double | 0x03],
	'null': ['null', jsval_tag_max_double | 0x04],
	'magic': ['magic value', jsval_tag_max_double | 0x05],
	'string': ['string', jsval_tag_max_double | 0x06],
	'symbol': ['symbol value', jsval_tag_max_double | 0x07],
	'gc_thing': ['garbage collector related value', jsval_tag_max_double | 0x08],
	'bigint': ['big integer (64-bit or 128-bit)', jsval_tag_max_double | 0x09],
	'object': ['object', jsval_tag_max_double | 0x0c]
}

jsid_type_string = 0x00
jsid_type_int_bit = 0x01
jsid_type_void = 0x02
jsid_type_symbol = 0x04
jsid_type_empty = 0x6
jsid_type_mask = 0x07

def __internal_jsid_type_int(__x):
	return (not (not (__x & jsid_type_int_bit)))

def __internal_jsid_type_string(__x):
	return (__x & jsid_type_mask) == jsid_type_string

def __internal_jsid_type_void(__x):
	if __js_debug__ == True:
		while False:
			if __x & jsid_type_mask == jsid_type_void:
				assert(__x == jsid_type_void)
	else:
		while False:
			pass

	return __x == jsid_type_void

def __internal_jsid_type_symbol(__x):
	return (__x & jsid_type_mask) == jsid_type_symbol

def __internal_jsid_type_empty(__x):
	if __js_debug__ == True:
		while False:
			if __x & jsid_type_mask == jsid_type_empty:
				assert(__x == jsid_type_empty)
	else:
		while False:
			pass

	return __x == jsid_type_empty

jsid_shape_type = {
	'int': ['integer', __internal_jsid_type_int],
	'string': ['string', __internal_jsid_type_string],
	'void': ['void', __internal_jsid_type_void],
	'symbol': ['symbol', __internal_jsid_type_symbol],
	'empty': ['empty', __internal_jsid_type_empty]
}

def arg_to_num(arg):
	if arg.startswith('0x'):
		v = int(arg, 0x10)
	else:
		v = int(arg, 0x0a)

	return v

def addr_extractor(arg):
	return arg_to_num(arg) & ((2 ** 47) - 1)

def tag_extractor(arg):
	return (arg_to_num(arg) >> 47)

class JSAddressExtractor(gdb.Command):
	def __init__(self):
		super(JSAddressExtractor, self).__init__("js-strip-addr", gdb.COMMAND_USER)

	def invoke(self, arg, from_tty):
		print(hex(addr_extractor(arg)))

class JSValueTag(gdb.Command):
	def __init__(self):
		super(JSValueTag, self).__init__("js-value-type", gdb.COMMAND_USER)

	def invoke(self, arg, from_tty):
		tag = tag_extractor(arg)

		for vtag in js_value_tag:
			if tag == js_value_tag[vtag][1]:
				vtype = js_value_tag[vtag][0]

		print("[*] addr: {}".format(hex(addr_extractor(arg))))
		print("[*] type: {}".format(vtype))

def get_js_string(addr_):
	vbuf = gdb.execute(
		"p (char *)((*(JSString *)({}))->d.inlineStorageLatin1)".format(hex(addr_)),
		to_string=True
	)

	(kaddr, buf) = vbuf.split(' = ')[1].rstrip(chr(0x0a)).split(' ')

	return ({'addr': kaddr, 'key': buf})

class JSString(gdb.Command):
	def __init__(self):
		super(JSString, self).__init__("js-string", gdb.COMMAND_USER)

	def get_string(self, addr_):
		return get_js_string(addr_)

	def invoke(self, arg, from_tty):
		entry = get_js_string(arg_to_num(arg))

		print("{} ({})".format(entry['key'], entry['addr']))

class JSObjectShape(gdb.Command):
	def __init__(self):
		super(JSObjectShape, self).__init__("js-shape-info", gdb.COMMAND_USER)

		# js::Shape count
		self.shape_count = 0

	def get_jsid_shape_bits(self, arg_):
		as_bits = gdb.execute(
			"p (*(js::GCPtrId *)(&(*(js::Shape *)({}))->propid_)).value.asBits".format(hex(arg_)),
			to_string=True
		)

		return as_bits.split(' = ')[1].rstrip(chr(0x0a))

	def get_jsid_string_value(self, propid_):
		return get_js_string(propid_ ^ jsid_type_string)

	def get_jsid_parent(self, addr_):
		vbuf = gdb.execute(
			"p (*(js::Shape *)({})).parent".format(hex(addr_)),
			to_string=True
		)

		return vbuf.split(' = ')[1].rstrip(chr(0x0a))

	def invoke(self, arg, from_tty):
		is_parent_null = False
		parent = arg_to_num(arg)
		vsep = ''

		while is_parent_null == False:
			as_bits_stripped = self.get_jsid_shape_bits(parent)

			print("{}[*] shape: {}".format(vsep, hex(parent)))
			print("{}[*] shape.propid_.asBits: {}".format(vsep, as_bits_stripped))

			as_bits_int = arg_to_num(as_bits_stripped)

			for vid in jsid_shape_type:
				if jsid_shape_type[vid][1](as_bits_int) == True:
					vtype = jsid_shape_type[vid][0]

			print("{}[*] shape(type): {}".format(vsep, vtype))

			if vtype == 'string':
				entry = self.get_jsid_string_value(as_bits_int)
			elif vtype == 'void' or vtype == 'empty':
				entry = None

			if entry != None:
				print("{}[*] shape(key): {} ({})".format(vsep, entry['key'], entry['addr']))

			parent = arg_to_num(self.get_jsid_parent(parent))

			print("{}[*] shape(parent): {}".format(vsep, hex(parent)))

			if parent == 0x0:
				is_parent_null = True
				vsep = ''
			else:
				vsep += ' '*(3)
				self.shape_count = self.shape_count + 1

class JSArrayObject(gdb.Command):
	def __init__(self):
		super(JSArrayObject, self).__init__("js-array-object", gdb.COMMAND_USER)

	def get_js_arrobj_group(self, addr_):
		vbuf = gdb.execute(
			"p (*(js::ArrayObject *)({})).group_".format(hex(addr_)),
			to_string=True			
		)

		return int(vbuf.rstrip(chr(0x0a)).split(' = ')[1], 0x10)

	def get_js_arrobj_shape(self, addr_):
		vbuf = gdb.execute(
			"p (*(js::ArrayObject *)({})).shape_".format(hex(addr_)),
			to_string=True
		)

		return int(vbuf.rstrip(chr(0x0a)).split(' = ')[1], 0x10)

	def get_js_arrobj_elements(self, addr_):
		vbuf = gdb.execute(
			"p (*(js::ArrayObject *)({})).elements_".format(hex(addr_)),
			to_string=True
		)

		return int(vbuf.rstrip(chr(0x0a)).split(' = ')[1].split("*) ")[1], 0x10)

	def invoke(self, arg, from_tty):
		addr = arg_to_num(arg)

		group_ = self.get_js_arrobj_group(addr)
		shape_ = self.get_js_arrobj_shape(addr)
		elements_ = self.get_js_arrobj_elements(addr)

		print("[*] array object: {}".format(hex(addr)))
		print("[*] array object(group_): {}".format(hex(group_)))
		print("[*] array object(shape_): {}".format(hex(shape_)))
		print("[*] array object(elements_): {}".format(hex(elements_)))

def registerAllCommands():
	JSAddressExtractor()
	JSValueTag()
	JSObjectShape()
	JSString()
	JSArrayObject()

# bootstrap all registered commands.
registerAllCommands()
