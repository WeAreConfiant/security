# by taha@confiant.com

import idc
import struct
import idautils
import zlib

# these are constant per OSX/Tarmac malware
xor_key = 0x33
xor_keystream =  ''.join(chr(x) for x in [0x4b, 0x00, 0xe0, 0x6e,0xf1, 0xd9, 0x13, 0x3f, 0x4a, 0x6e, 0xf8, 0x9f, 0xd5, 0x9c])

def decompress(data):
	try:
		data2 = zlib.decompressobj()
		decompressed_data = data2.decompress(data)
		decompressed_data += data2.flush()
		return decompressed_data
	except zlib.error as e:
		print(e)
		return ''

# function to inflate decoded data
def infl4te():
	try:
		with open('compressed.dat', 'rb') as content_file:
			content = content_file.read()
		result = decompress(content)
		print('Decompressed data: ' + result)
		return result
	except Exception as e: print(e)

# function  decrypt data via the xor_keystream, should call infl4te() at the end
def decrypt(xor_keystream, encrypted_string):
	with open('compressed.dat', 'wb') as f:
		i = 0
		max = len(xor_keystream)
		for enc in encrypted_string:
			if i == max:
				i = 0
			tmp = ord(xor_keystream[i]) ^ ord(enc)
			f.write(chr(tmp))
			i += 1

def find_encrypted_strings(opcode, start, end):
	ea = start
 	ret = []
    	ea = idc.FindBinary(ea, 1, opcode)
    	while ea != idc.BADADDR and ea < end:
        	ret.append(ea)
        	ea = idc.FindBinary(ea + 4, 1, opcode)
    	return ret
  
def extract_encrypted_string(ea):
	encrypted_string = ''
	check_first_bytes = 0
	string_origin = ea
	# Read until we find a 0x0 or 0x33DA.. 
	while 1:
		c = Byte(ea)
		if c == 0x00:
			tmp0 = Byte(ea+1)
			if tmp0 == 0x00:
				break
		if check_first_bytes:
			if c == 0x33:
				tmp = c
				c = Byte(ea+1)
				if c == 0xDA:
					break
				else:
					encrypted_string += chr(tmp)
					ea+=1
			else:
				encrypted_string += chr(c)
				ea+=1
		else:
			encrypted_string += chr(c)
			ea+=1
			check_first_bytes = 1
	print 'found string of length %i at %s' % (len(encrypted_string), hex(string_origin))
	return encrypted_string

# Limit the scope of our work to __const 
for ea in Segments():
	if SegName(ea) == "__const":
		start = SegStart(ea)
		end = SegEnd(ea)
    		print 'analysing: %s: %x-%x'%(SegName(ea), start, end)
		encrypted_strings_ea = find_encrypted_strings("0xda33", start, end) # corresponds to the begining of an encrypted string
		print 'found %i encrypted strings' % (len(encrypted_strings_ea))
		for address in encrypted_strings_ea:
			encrypted_string = extract_encrypted_string(address)
			decrypt(xor_keystream, encrypted_string) # decodes the string
			final_decoded_string = infl4te() # call zlib inflate
			MakeComm(address, final_decoded_string) # settings comments
			for x in XrefsTo(address, flags=0):
				print 'found xrefs at %s for %s' %(hex(x.frm), hex(address))
				print 'adding comment to xrefs'
				MakeComm(x.frm, final_decoded_string) # settings xrefs comments
