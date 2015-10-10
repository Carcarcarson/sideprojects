#!/usr/bin/python
#Carson Harmon, harmon35@purdue.edu 
#lets make a web scanner that will scan a specific host to see what ports are open. 
#caveat, have to have IP in your arp table (arp -n) linux. 
#learn how to arp sweep the network.

"""
Objective, create simple network scanner.

If you want to use it in any directory throw it into your path. 
#!/usr/bin/python
export PATH=/my/directory/with/pythonscript:$PATH
"""


import os #for root
import sys #for exit 
import ast #thaks stackover flow. 
import logging #get rid of error 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #get rid of annoying warning message
from scapy.all import * #for packet manipulation. 
import argparse #command line input.


#to take things from command line
parser = argparse.ArgumentParser()
parser.add_argument("-t", metavar = "t", help="Target IP")
parser.add_argument("-p", metavar = "p", help="Target Ports")
args = parser.parse_args()


#main scanner class.
class ScanShit:
	def __init__(self, IP_ADDR, PORTS): 
		#Create packet objects and define instance variables.
		self.i = IP()
		self.t = TCP()
		self.PORTS = PORTS
		self.IP_ADDR = IP_ADDR
		self.i.dst = IP_ADDR
		self.t.flags = "S"

	#make sure the user is root. 
	def RunRoot(self):
		if os.getuid() != 0:
			print "*****************************************"
			print "EXITING: ERROR, RUN AS ROOT"
			print "*****************************************"
			sys.exit()
	#Sometimes we won't have the target's mac addr in our arp table, if we ping it we implicitly grab the mac addr.
	def getarp(self): 
		print "----------------------------"
		print "CHECKING TO SEE IF HOST IS UP"
		print "----------------------------"
		im = ICMP()
		repcheck = sr(self.i/im, timeout=10)
		#8 means we got good reply. you can look for yourself but honestly I'd just go with it.
		if repcheck[0][0][0].type == 8:
			return 8
		else: 
			print "---------------------------------------"
			print "Hey this shit doesnt always work sorry!" #sometimes when you scan in 2 short of an interval you'll get some type of packet loss.
			print "---------------------------------------"
			sys.exit()
	
	#The scanning method. 
	def Scan(self):
		print "----------------------------"
		print "Scanning target!"
		print "----------------------------"
		self.t.dport = self.PORTS
		ans, unans = sr(self.i/self.t, timeout=10)
		for i in range(0, len(self.PORTS)):
			if ans[i][1].getlayer(TCP).flags == 0x14: #this is hex for the RA flag. 
				print self.IP_ADDR + ":" + str(ans[i][0].getlayer(TCP).dport) + " is " + "Closed"
			if ans[i][1].getlayer(TCP).flags == 0x12: #this is hex for the SA flag. 
				print self.IP_ADDR + ":" + str(ans[i][0].getlayer(TCP).dport) + " is " + "Open"
		
	
def main():
	
	IP_ADDR = args.t
	PORTS = args.p
	PORTS = ast.literal_eval(PORTS) #when we get our argument from commandline the list is a string ex:"[22,80]", this makes it a list, [22,80]
	s = ScanShit(IP_ADDR, PORTS)
	s.RunRoot()
	if s.getarp() == 8: #slightly redundant 
		s.Scan()

		
if __name__ == '__main__':
	main()