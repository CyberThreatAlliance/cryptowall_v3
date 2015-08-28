#!/usr/bin/env python
# This script will take a single PCAP and attempt to parse it for CryptoWall
# version 3 traffic. The decrypted traffic is written to STDOUT. 

import dpkt, re, base64, sys, string
from binascii import *

was_last_req_cw3 = False
last_key = ""

def unmangle(data_string):
	'''
	Takes a string of data and re-arranges it in order. This technique is used
	by CryptoWall v3 to create the actual RC4 key used for decryption.
	'''
	buf = list(data_string) + ["\x00"]
	sz_key = len(buf)
	while sz_key:
		sz_key -= 1
		for i in range(0, sz_key):
			if ord(buf[i]) >= ord(buf[i+1]):
				v1 = buf[i+1]
				buf[i+1] = buf[i]
				buf[i] = v1
	return ''.join(buf).lstrip("\x00")


def rc4_crypt(data, key):
	'''
	RC4 routine. Pretty straight forward. 
	'''
	S = range(256)
	j = 0
	out = []
	for i in range(256):
		j = (j + S[i] + ord( key[i % len(key)] )) % 256
		S[i] , S[j] = S[j] , S[i]
	i = j = 0
	for char in data:
		i = ( i + 1 ) % 256
		j = ( j + S[i] ) % 256
		S[i] , S[j] = S[j] , S[i]
		out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
	return ''.join(out)


def parse_response(http, stream):
	'''
	Takes http response data and look to see if it is responding to a previously
	seen CryptoWall v3 request. If so, it will attempt to parse the response and
	display this to STDOUT.
	'''
	global was_last_req_cw3, last_key
	body = http.body
	if was_last_req_cw3:
		if re.findall("^[a-fA-F0-9\n ]+$", body):
			for s in stream.split("\r\n"):
				print "\t< %s" % s
			t = re.findall("[a-fA-F0-9]{4,}", body)
			if t:
				decrypted = rc4_crypt(unhexlify("".join(t)), last_key)
				if all(c in string.printable for c in decrypted):
					print "\t< [decrypted] %s" % decrypted.replace("\n", "\n\t  ")
		if body.startswith("\x89PNG"):
			for s in stream.split("\r\n\r\n")[0].split("\r\n"):
				print "\t< %s" % s
			print "\t< [truncated] %r" % body[0:20]
		print

def parse_request(http, stream):
	'''
	Takes http request data and looks for characteristics of a CryptoWall v3 http
	request. If found, it will attempt to decrypt the provided POST data and 
	output this to STDOUT. 
	'''
	global was_last_req_cw3, last_key
	uri = http.uri
	host = http.headers['host']
	url = ''.join(["http://", host, uri])
	res = re.findall("\.php\?\w+\=(\w+)", uri)
	if res != []: 
		was_last_req_cw3 = True
		for s in stream.split("\n"):
			print "> %s" % s
		data = unhexlify(http.body.split("=")[1])
		new_key = unmangle(res[0])
		last_key = new_key
		decrypted = rc4_crypt(data, new_key)
		if "{" in decrypted and "}" in decrypted:
			print "> [decrypted] %s" % decrypted
		print
	else:
		was_last_req_cw3 = False


def parse_pcap_file(filename):
	'''
	Parses through a PCAP file looking for http requests and responses. If found,
	they are provided as argument to the relevant parse_* functions.

	Reference: 
	https://blog.bramp.net/post/2010/01/10/follow-http-stream-with-decompression/
	'''
	f = open(filename, 'rb')
	pcap = dpkt.pcap.Reader(f)
	conn = dict()
	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		if eth.type != dpkt.ethernet.ETH_TYPE_IP:
			continue
		ip = eth.data
		if ip.p != dpkt.ip.IP_PROTO_TCP:
			continue
		tcp = ip.data
		ip_tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
		if ip_tupl in conn:
			conn[ip_tupl] = conn[ip_tupl] + tcp.data
		else:
			conn[ip_tupl] = tcp.data
		try:
			stream = conn[ip_tupl]
			if stream[:4] == 'HTTP':
				http = dpkt.http.Response(stream)
				parse_response(http, stream)
			else:
				http = dpkt.http.Request(stream)
				if http.method == "POST":
					parse_request(http, stream)
			stream = stream[len(http):]
			if len(stream) == 0:
				del conn[ip_tupl]
			else:
				conn[ip_tupl] = stream
		except:
			pass
	f.close()


if __name__ == '__main__':
	if len(sys.argv) <= 1:
		print "%s [pcap file]" % __file__
		sys.exit(2)
	parse_pcap_file(sys.argv[1])