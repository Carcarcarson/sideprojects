"""
Carson Harmon
harmon35@purdue.edu
Python 2.7.6 

2 do list: create becon and listener, change server to send data back, make less hard codey
p2p attempt 2 lmao
"""

#various practice 
#ideas ideas ideas
#send becon
#thread and listen to becon calls
#if hear becon call to you initiate server. 
#talk via client and server 
#if you recieve a syn packet via 
import threading 
import os
import sys
import socket
import time
import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#make sure everything is being run as root.
def RunRoot():
	if os.getuid() != 0:
		print "*****************************************"
		print "EXITING: ERROR, RUN AS ROOT"
		print "*****************************************"
		sys.exit()

#Server object
#Change server to send data back. #################################################################
class Server(threading.Thread):
	def __init__(self): #maybe call (self, ip) where ip = raw_input("ur ip addr")
		threading.Thread.__init__(self)
		self.port = 1337 
		self.ip = "192.168.1.12"
		self.size = 1024
		self.server = None

	def serve(self):
		try:
			self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #check this line compared to orig
			self.server.bind((self.ip, self.port))
			self.server.listen(10) 
			self.server.accept() #still get err107 transport endpoint not connected 
			
		except socket.error, (value,message): #this works
			if self.server:
				self.server.close()
			print "Failed to create socket object, check your bind IPaddr for correction"
			sys.exit(1)
	
	def run(self):
		self.serve()
		running = True 
		print "server running....."
		while running:

			#sc, sockname = self.server.accept()
			data_recv = self.server.recv(1024)
			print data_recv
			if not data:
				self.server.close()
				running = False
#client object
class Client(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.target = "192.168.1.14"
		self.target_port = 1337
		self.sock = None

	def conn(self):
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((self.target, self.target_port))
			print "conn established"
			while True:
				data = raw_input(">>   ")
				if data:
					self.sock.sendall(data)
					continue
				if data == "quit":
					break
					sys.exit(2)
		except socket.error, (value, message):
    			self.sock.close()
    			sys.exit(1)

class Becon:
	def __init__(self):
		pass
	"""
	becon, needs to send out tcp syn requests to said ports
	we should set up a listener, or even better an option to listen, then user conf to connect to said host
	The idea would be you run the program, start your listener, if you hear something from the listener you kill
	the becon initiate the server and chat. 
	"""

if __name__ == "__main__":
	RunRoot()
	s = Server()
	c = Client()
	s.run()
	"""
	if packet has Syn flag to port 1337, iniiate server
	threading.Thread(target = s.run).start()
	if becon has ack flag iniate client side connection to said server
	threading.Thread(target = c.conn).start()
	"""

