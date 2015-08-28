# IDAPython script that can be used to generate the dynamically built import 
# address table in an unpacked CryptoWall version 3 sample. 

debug = True

def get_all_enum_constants():
	'''
	Returns hash of constant numerical representations. Value of each key is an 
	array containing the constant name (array[0]) and the constant ID (array[1]).
	'''
	constants = {}
	all_enums = GetEnumQty()
	for i in range(0, all_enums):
		en = GetnEnum(i)
		first = GetFirstConst(en, -1)
		v1 = GetConstEx(en, first, 0, -1)
		name = GetConstName(v1)
		constants[int(first)] = [name, en]
		while True:
			first = GetNextConst(en, first, -1)
			v1 = GetConstEx(en, first, 0, -1)
			name = GetConstName(v1)
			if first == 0xFFFFFFFF:
				break
			constants[int(first)] = [name, en]
	return constants

def modify_push_to_enum(addr, constants):
	'''
	'''
	constant_id = GetOperandValue(addr, 0)
	if constant_id in constants:	
		enum_id = constants[constant_id]
		OpEnumEx(addr, 0, enum_id[1], 0)
		return enum_id[0]
	else:
		return None


ALL_CONSTANTS = get_all_enum_constants()


def generate_iat_struct(data):
	'''
	This will generate a structure that contains the new IAT.
	'''
	name = "CW3_IAT"
	sid = AddStrucEx(-1, name, 0)
	for k,v in data.iteritems():
		if debug:
			print "[+] Debug: [Offset] %d | [Name] %s" % (k, v)
		AddStrucMember(sid, v, k, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)
	print "[+] Structure %s created." % name


def enum_for_xrefs(f_addr):
	'''
	This function will search for cross-references to a given function. 
	'''
	iat_structure = {}
	for x in XrefsTo(f_addr, flags=0):
		curr_addr = x.frm
		addr_m_20 = curr_addr-20

		current_constant = None
		while curr_addr >= addr_m_20:
			curr_addr = PrevHead(curr_addr)
			if GetMnem(curr_addr) == "push":
				data = GetOperandValue(curr_addr, 0)
				if data > 0xFFFF and data < 0xFFFFFFFF:
					enum = modify_push_to_enum(curr_addr, ALL_CONSTANTS)
					if enum:
						current_constant = enum

		curr_addr2 = x.frm
		addr_p_20 = curr_addr2+20
		while curr_addr2 <= addr_p_20:
			curr_addr2 = NextHead(curr_addr2)
			if GetMnem(curr_addr2) == "mov":
				possible_iat = GetOperandValue(curr_addr2, 1)
				if IAT == possible_iat:
					curr_addr2 = NextHead(curr_addr2)
					if GetMnem(curr_addr2) == "mov" and GetOpnd(curr_addr2, 1) == "eax":
						offset = GetOperandValue(curr_addr2, 0)
						if offset == 1 and current_constant != None:
							iat_structure[0] = current_constant
						elif current_constant != None:
							iat_structure[offset] = current_constant
	return iat_structure


def find_pattern(pattern, max_attempt=5):
	'''
	Find a pattern in a binary, and provide any references to said pattern.
	'''
	addr = MinEA()
	results = []
	for x in range(0, max_attempt):
		addr = idc.FindBinary(addr, SEARCH_DOWN, pattern)
		if addr != idc.BADADDR:
			if addr not in results:
				results.append(addr)
	return results


def find_function_start(ea):
	'''
	Find the starting address of the function a particular address resides in.
	'''
	func = idaapi.get_func(ea)
	if func:
		return func.startEA
	else:
		return None


def find_next_call_address(ea, max_attempt=5):
	'''
	Attempt to find the next call instruction after a particular address.
	'''
	for x in range(0, max_attempt):
		if GetMnem(ea) == "call":
			return GetOperandValue(ea,0)
		ea = NextHead(ea)
	return None


def find_load_function_by_hash():
	'''
	We're looking for traits present in an important function that resides in a
	CryptoWall v3 sample.
	'''
	zwallocatevirtualmemory = find_pattern('68 74 A5 20 D8')
	ldrloaddll = find_pattern('68 F2 79 36 18')
	if len(zwallocatevirtualmemory) == 1 and len(ldrloaddll) == 1:
		zw = zwallocatevirtualmemory[0]
		ldr = ldrloaddll[0]
		zw_func = find_function_start(zw)
		ldr_func = find_function_start(ldr)
		if zw_func == ldr_func and zw_func:
			# We've got a candidate.
			zw_call = find_next_call_address(zw)
			ldr_call = find_next_call_address(ldr)
			if zw_call == ldr_call and zw_call:
				return zw_call
	return None


def find_lib_by_hash():
	'''
	We're looking for traits present in an important function that resides in a
	CryptoWall v3 sample.
	'''
	ws2_32 = find_pattern('68 15 E8 34 F7')
	wininet = find_pattern('68 F7 65 F4 C7')
	if len(ws2_32) == 1 and len(wininet) == 1:
		ws2 = ws2_32[0]
		win = wininet[0]
		ws2_32_func = find_function_start(ws2)
		wininet_func = find_function_start(win)
		if ws2_32_func == wininet_func and ws2_32_func:
			# We've got a candidate.
			ws2_32_call = find_next_call_address(ws2)
			wininet_call = find_next_call_address(win)
			if ws2_32_call == wininet_call and ws2_32_call:
				return ws2_32_call
	return None


def find_load_func_various_libs_by_hash():
	'''
	We're looking for traits present in an important function that resides in a
	CryptoWall v3 sample.
	'''
	writefile = find_pattern('68 12 56 E9 CC')
	getusername = find_pattern('68 C2 AF A2 AD')
	if len(writefile) == 1 and len(getusername) == 1:
		write = writefile[0]
		getuser = getusername[0]
		write_func = find_function_start(write)
		getuser_func = find_function_start(getuser)
		if write_func == getuser_func and write_func:
			# We've got a candidate.
			write_call = find_next_call_address(write)
			getuser_call = find_next_call_address(getuser)
			if write_call == getuser_call and write_call:
				return write_call
	return None


# Trying to find the first important function.
load_function_by_hash_addr = find_load_function_by_hash()
if debug and load_function_by_hash_addr:
	print "[+] Found load_function_by_hash at 0x%x" % load_function_by_hash_addr

# Trying to find the second important function.
find_lib_by_hash_addr = find_lib_by_hash()
if debug and find_lib_by_hash_addr:
	print "[+] Found find_lib_by_hash at 0x%x" % find_lib_by_hash_addr

# Trying to find the last important function.
load_functions_various_libraries_addr = find_load_func_various_libs_by_hash()
if debug and load_functions_various_libraries_addr:
	print "[+] Found load_functions_various_libraries at 0x%x" % load_functions_various_libraries_addr

a1 = enum_for_xrefs(load_function_by_hash_addr)
a2 = enum_for_xrefs(find_lib_by_hash_addr)
a3 = enum_for_xrefs(load_functions_various_libraries_addr)
# Aggregate a list of all references to libraries and functions by their CRC32
# hash representation. 
a_final = dict(a1.items() + a2.items() + a3.items())
# Generate a struct using the data previously discovered. 
generate_iat_struct(a_final)