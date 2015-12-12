'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    client.py
--
--  PROGRAM:        Covertly sends data by manipulating the TCP header field source port to a specified server.
--
--  FUNCTIONS:      realPacketCrafter(destIP, destPort, letter), 
--                  fakePacketCrafter(destIP, destPort), 
--                  getSpoofedIP(), 
--                  encryptMessage(letter).
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
import random
from scapy.all import *

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       realPacketCrafter
--  Parameters:
--      destIP
--        The user specified server IP address
--      destPort
--        Either a user specified port (Preferred port 80) or randomized port.
--      letter
--        The character that will be hidden in the packet.
--  Return Values:
--      craftedPacket
--  Description:
--      Function to craft the packet with the specified values as well as the key
--      identified of TTL 188 to let the server know it's the covert data packet.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def realPacketCrafter(destIP, destPort, letter):
    #Convert ASCII letter to decimal value
    letter = ord(letter)
    destPort = int(destPort)
    #Note that the time to live is set for 188 seconds - this is the key that the server will look for.
    craftedPacket = IP(src=getSpoofedIP(), dst=destIP, ttl=188)/TCP(sport=encryptMessage(letter), dport=destPort, flags="SA")
    return craftedPacket

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       fakePacketCrafter
--  Parameters:
--      destIP
--        The user specified server IP address
--      destPort
--        Either a user specified port (Preferred port 80) or randomized port.
--  Return Values:
--      craftedPacket
--  Description:
--      Function to craft a "padding" packet to help hide the real covert packet. It 
--      sends the packet with TTL of 64 as to not trigger the server's filter.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def fakePacketCrafter(destIP, destPort):
    destPort = int(destPort)
    #Difference between fake and real packet is the (recommended) TTL of 64 and no data of interest being sent.
    craftedPacket = IP(src=getSpoofedIP(), dst=destIP, ttl=64)/TCP(dport=destPort, flags="SA")
    return craftedPacket

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       getSpoofedIP
--  Parameters:
--      None
--  Return Values:
--      ipAddress
--  Description:
--      Function to get the current machine's IP address and change the last octect
--      Essentially spoofing the IP addresses of other stations within the subnet.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def getSpoofedIP():
  #getfqdn used in place of gethostname since some systems return 127.0.0.1
  ipAddress = socket.gethostbyname(socket.getfqdn())
  #ipAddress = socket.gethostbyname(socket.gethostname())
  #Split the different IP sections into their own variables for manipulation
  ip1, ip2, ip3, ip4 = ipAddress.split('.')
  #Choose a random number between 5 and 30 to use as the spoofed source IP
  #Convert randomized number into a string in order to concatenate it.
  ip4 = str(random.randint(5,30))
  ipAddress = ip1 + "." + ip2 + "." + ip3 + "." + ip4
  return ipAddress

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       encryptMessage
--  Parameters:
--      letter
--        The character from the user specified message that will be encrypted
--  Return Values:
--      letter
--  Description:
--      Function to "encrypt" to decimal value of the ASCII character by adding 8505
--      in order to make it more difficult to see the message being transferred.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''  
def encryptMessage(letter):
  letter += 8505
  return letter

#Main fuction
if __name__ == "__main__":
  destinationIP = raw_input("Enter the server's IP address: ")
  destinationPort = raw_input("Enter your desired destination port (leave it blank if you wish to have it randomized): ")
  #If the user didn't choose a destination port, randomize on between 1000 and 8505
  if destinationPort == "":
    destinationPort = random.randint(1000,8505)
  #In a while loop in case the user wants to send multiple messages.
  while True:
    #Input from the user of what message data to send covertly over to the server
    data = raw_input("Enter message to covertly send to server: ")
    data += "\n"
    print "Sending message to server: " + data
    letterList = []
    #Move all the data into a list for later manipulation and use.
    for letter in data:
        letterList.append(letter)
    boolCheck = 1
    while (boolCheck):
        #Randomize the packet send interval so it's not so uniform.
        time.sleep(random.randint(1,5))
        #Randomizer to lower detectability by sending useless packets between actual crafted data packet
        randNum = random.randint(1,2)
        #If the random number equals 2, send the real packet, else send a fake packet.
        if randNum == 2:
            #If the list is empty, flip the checker value and get out of the while loop.
            if len(letterList) == 0:
                boolCheck = 0
                print "Message successfully sent to server."
            #If the list is not empty, send the crafted packet
            else:
                #Remove the first item in the list and assign the value to letter.
                letter = letterList.pop(0)
                packet = realPacketCrafter(destinationIP, destinationPort, letter)
                send(packet)
        #If the list is empty, flip the checker value and get out of the while loop.
        elif len(letterList) == 0:
              boolCheck = 0
              print "Message successfully sent to server."
        else:
            packet = fakePacketCrafter(destinationIP, destinationPort)
            send(packet)
