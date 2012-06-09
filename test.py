#!/usr/bin/python

import sys
import os
import sys
import struct
import pcap as lib

	

def userInput(message):
	return raw_input( message )
	
def critError( message ):
	print "Critical Error: " + message
	sys.exit(1)


def main():
	wfile = open("output.pcap", "wb")
	pcapObj = lib.pcap( userInput( "Enter Pcap File: " ) )
	
	#for byte in rfile.read():
	#	wfile.write(byte)
	
	header = pcapObj.getHeader()
	for byte in header.getMagic():
		wfile.write(byte)
		
	if(header.checkMagic()):
		print "Magic Number Valid.."
		
	wfile.close()
	
main()