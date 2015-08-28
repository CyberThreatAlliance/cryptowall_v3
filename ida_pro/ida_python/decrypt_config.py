# To be run on an unpacked CryptoWall v3 sample. Results not guaranteed.
# This IDAPython script can be used to attempt to decrypt and subsequently 
# parse the C2 information contained within a CryptoWall version 3 sample.

import base64
import sys
from struct import *

def rc4_crypt(data, key):
	'''
	Simple RC4 algorithm function
	'''
	S = range(256)
	j = 0
	out = []

	for i in range(256):
		j = (j + S[i] + ord(key[i % len(key)])) % 256
		S[i], S[j] = S[j], S[i]
	i = j = 0

	for char in data:
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j] , S[i]
		out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
	return ''.join(out)

 
def all_segments():
	'''
	This function will return all segments contained in a provided executable.
	'''
	ret = {}
	f = FirstSeg()
	while f != 0xffffffff:
		ret[SegName(f)] = f
		f = NextSeg(f)
	return ret


def parse_config(data):
	'''
	This function will parse the decrypted C2 information, and provide the 
	resulting URLs in an array.
	'''
	pos = 0
	ret = []
	while pos < len(data):
		length = unpack("I", data[pos:pos+4])[0]
		pos += 4
		c2 = data[pos:pos+length]
		ret.append("C2 : %s" % c2)
		pos += length
		pos += 2
	return ret


# Iterate through the data segment of the malware looking for a potential 
# candidate that might hold the encrypted C2 information in the CryptoWall v3
# sample.
segs = all_segments()
if '.data' in segs:
	data_section = segs['.data']
	for ea in range(data_section, SegEnd(data_section)):
		d = Dword(ea)
		if d > 0x8 and d < 0x20:
			key_size = d
			key_pos = ea+4
			key = GetString(key_pos, -1, ASCSTR_C)
			if key:
				if len(key) == key_size:
					print "[*] Possible encrypted configuration blob identified at %s" % (hex(ea))
					blob_size_pos = key_pos + len(key) + 1
					blob_size = Dword(blob_size_pos)
					blob_pos = blob_size_pos+4
					end = blob_pos + blob_size
					blob = ""
					for c in range(blob_pos, end):
						blob += chr(Byte(c))
					data = rc4_crypt(blob, key)
					parsed = parse_config(data)
					for p in parsed:
						print "[+]", p
					break
		ea+=4
