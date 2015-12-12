'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    server.py
--
--  PROGRAM:        Receives the data by extracting the TCP header field source port's value.
--
--  FUNCTIONS:      getMessage(packet), 
--                  decryptMessage(letter), 
--
--  DATE:           September 21, 2015
--
--  REVISIONS:      September 26, 2015
--
--  NOTES:
--  The program requires "Scapy" API and root user in order to work properly
--  http://www.secdev.org/projects/scapy/
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
#!/usr/bin/env python
import sys
from scapy.all import *

# If the packet is TCP and with the key TTL of 188, then grab the secret message.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       getMessage
--  Parameters:
--      packet
--        The filtered TCP packet sniffed from the main function.
--  Return Values:
--      None
--  Description:
--      Function to filter the TCP packet and see if the key identifier, TTL==188.
--      Once that condition is true, it will extract the value from the source port (hidden data)
--		And print it out to the terminal as well as write to a text file for later revision.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def getMessage(packet):
	ttl = packet[IP].ttl
	if ttl == 188:
		#Pull the data that was hidden in the source port
		letter = packet['TCP'].sport
		#Opens a text file to be written to.
		file = open("dataMessage.txt", "a")
		#Decrypt the letter
		file.write(decryptMessage(letter))
		file.close()
		sys.stdout.write(decryptMessage(letter))

#Subtract 8505 to the ASCII value in order to decrypt the "real" ASCII character
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       decryptMessage
--  Parameters:
--      letter
--        The decimal value extracted from the filtered packet.
--  Return Values:
--      letter
--  Description:
--      Function to take the extracted decimal value from the source port by
--		subtracting 8505 to it and then converting it back to ASCII and returning that value.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def decryptMessage(letter):
	letter -= 8505
	# chr to convert the decimal value back to ASCII
	letter = chr(letter)
	return letter

# Main program
if __name__ == "__main__":
	sniff(filter="tcp", prn=getMessage)
