#!/usr/bin/python

import struct
import protos


#Notes:
#
# ---------------------------------------------------------------------------
# Ethernet protocol specifications (IEEE 802.3) define the following rules:
#
# 	Bytes 00-05 identify the Destination Ethernet address
# 	Bytes 06-0B identify the Source Ethernet address
# 	Bytes 0C-0D identify the Ethernet type
# ---------------------------------------------------------------------------
#
#
# pcapHeader class - this class constructs an object that represents the global properties of the pcap file.
#
# The file format can be found at: http://wiki.wireshark.org/Development/LibpcapFileFormat 
#
#


#PcapHeader Class:
#	This class represents the global header of a pcap file.
#	To use this class, at least 8 bytes of data need to be sent in.

#TODO:
#	Implement:
#		Layer 2 Parsing
#		Layer 3 Parsing
#		Higher (optional) libraries (HTTP, etc.)
#		How to measure when we are done with bytes in the file?
#		Check endianess


class pcapHeader():
	def __init__(self, data):
		#Initialize the header structure (dictionary)
		self.header = 	{ 	'magic_number' 	: '',
							'version_major' : '',
							'version_minor' : '',
							'thiszone'		: '',
							'sigflags'		: '',
							'snaplen'		: '',
							'network'		: ''
						}
		#Set the values
		#for byte in data[:4]:
		self.header['magic_number'] = data[:4]
		
		#Set the value of the endian(ness)
		self.endian = 1 if self.header['magic_number'] == '\xd4\xc3\xb2\xa1' else 0

		#Set the remainder of the values according to endian
		self.header['version_major'] = self.reverse(data[4:6])
		self.header['version_minor'] = self.reverse(data[6:8])
		self.header['thiszone'] = self.reverse(data[8:12])
		self.header['sigflags'] = self.reverse(data[12:16])
		self.header['snaplen'] = self.reverse(data[12:16])
		self.header['network'] = self.reverse(data[16:20])
		
		print "Magic Number: " + self.getMagic_Readable()
		print "Version (Major): " + self.getMajorVersion_Readable()
		print "Version (Minor): " + self.getMinorVersion_Readable()
		#print "This Zone: " + self.getThisZone_Readable()
		#print "SigFlags: " + self.getSigFlags_Readable()
		#print "Snaplen: " + self.getSnapLen_Readable()
		#print "Network: " + self.getNetword_Readable()
		
	def reverse(self, value):
		return value if self.endian else value[::-1]
		
	def getMagic(self):
		return self.header['magic_number']
		
	def checkMagic(self):
		return (self.header['magic_number'] == '\xd4\xc3\xb2\xa1' or self.header['magic_number'] == '\xa1\xb2\xb3\xd4')
		
	def getMagic_Readable(self):
		magic_readable = ""
		for byte in self.header['magic_number']:
			magic_readable += hex ( ord ( byte ) ) + " "
		return magic_readable
		
	def getMajorVersion_Readable(self):
		version_readable = ""
		for byte in self.header['version_major']:
			version_readable += hex( ord( byte ) ) + " "
		return version_readable
	
	def getMinorVersion_Readable(self):
		version_readable = ""
		for byte in self.header['version_minor']:
			version_readable += hex ( ord ( byte ) ) + " "
		return version_readable
	
#Pcap Class (Custom... Hope this works)

def openPcap (fileName):
	try:
		rfile = open (fileName, "rb")
		return rfile
	except IOError as e:
		critError ("File does not exist")

class pcap():
	def __init__(self, file):
		#Open the file as a binary file to read bytes at a time
		self.file = openPcap( file )
		#Set the header (uses the first 8 bytes)
		self.header = pcapHeader(self.file.read(8))
		self.sessions = {}
		self.addresses = []
		
	def getHeader(self):
		return self.header
		
	#def parse(self):
	#	try:
	#		packet = 

	