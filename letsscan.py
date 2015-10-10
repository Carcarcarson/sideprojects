#scanner
#python 2.7.6 
#Carson Harmon, harmon35@purdue.edu 
#lets make a web scanner that will scan a specific host to see what ports are open. 
#caveat, have to have IP in your arp table (arp -n) linux. 
#learn how to arp sweep the network.

"""
Objective, create user friendly, somewhat simple, network scanner. 
DONE give option to choose ports and IP's 
give option to ARP the network--------------------------------------instead we should try and arp probe of target IP and if fail report failure and quit.
DONE Better user feedback 
Port to andriod
"""


import os #for root
import sys #for exit 
import ast #thaks stackover flow. 
import logging #get rid of error 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * #for packet manipulation. 
import argparse

parser = argparse.ArgumentParser()
# parser.add_argument("-a", metavar="a", help="Arp probe")
parser.add_argument("-t", metavar = "t", help="Target IP")
parser.add_argument("-p", metavar = "p", help="Target Ports")
args = parser.parse_args()
# print args.p
# print type(args.p)


class ScanShit:
	def __init__(self, IP_ADDR, PORTS): 
		self.i = IP()
		self.t = TCP()
		#PORTS = [22, 80]
		#have to have the mac addr in the arp table.
		#IP_ADDR = "192.168.9.158"
		self.PORTS = PORTS
		self.IP_ADDR = IP_ADDR
		self.i.dst = IP_ADDR
		self.t.flags = "S"
	#make sure you are root. 
	def RunRoot(self):
		if os.getuid() != 0:
			print "*****************************************"
			print "EXITING: ERROR, RUN AS ROOT"
			print "*****************************************"
			sys.exit()
	def getarp(self): 
		print "----------------------------"
		print "CHECKING TO SEE IF HOST IS UP"
		print "----------------------------"
		im = ICMP()
		repcheck = sr(self.i/im, timeout=10)
		if repcheck[0][0][0].type == 8:
			return 8
		else: 
			print "---------------------------------------"
			print "Hey this shit doesnt always work sorry!"
			print "---------------------------------------"
			sys.exit()
	
	def Scan(self):
		#for PORT in self.PORTS:
		print "----------------------------"
		print "Scanning target!"
		print "----------------------------"
		self.t.dport = self.PORTS #PORT
		helpme, donthelp = sr(self.i/self.t, timeout=10)
		# print helpme
		# print "--------------------------"
		# print helpme[0][0].getlayer(TCP).dport
		# print "--------------------------"
		# print helpme[1][0].getlayer(TCP).dport
		# print "--------------------------"
		for i in range(0, len(self.PORTS)):
			if helpme[i][1].getlayer(TCP).flags == 0x14: #nope 
				print self.IP_ADDR + ":" + str(helpme[i][0].getlayer(TCP).dport) + " is " + "Closed"
			if helpme[i][1].getlayer(TCP).flags == 0x12:
				print self.IP_ADDR + ":" + str(helpme[i][0].getlayer(TCP).dport) + " is " + "Open"
		
	
def main():
	# PORTS = args.p
	# PORTS = ast.literal_eval(PORTS) #get rid of string shit
	# IP_ADDR = raw_input(">>> Gib dst addr  ")
	IP_ADDR = args.t                     #this one works! "192.168.10.53"
	#PORTS = [22, 80]
	PORTS = args.p
	PORTS = ast.literal_eval(PORTS)
	
	s = ScanShit(IP_ADDR, PORTS)
	s.RunRoot()
	# s.getarp()
	if s.getarp() == 8:
		s.Scan()
if __name__ == '__main__':
	main()