"""
Carson Harmon
harmon35@purdue.edu
Python 2.7.6 

p2p attempt 2 lmao
"""

#various practice 

import threading 
import sys
import socket
import time

#Server object
class Server(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.port = 1337 
		self.ip = "192.168.1.24"
		self.size = 1024
		self.server = None

	def serve(self):
		try:
			self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.server.bind((self.ip, self.port))
			self.server.listen(10)
		except socket.error, (value,message):
			if self.server:
				self.server.close()
			print "u failed m8 g3t r3kt m8 gr8 job m8 l8er m8"
			sys.exit(1)
	
	def run(self):
		self.serve()
		running = True 
		print "server running....."
		while running:
			sc, sockname = self.server.accept()
			print "connection from %s" % sockname
			data_recv = self.server.recv(self.size)
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
				self.sock.sendall(data)
				continue
		except socket.error, exc:
			print "Caught exception socket.error: %s" % exc
    		self.sock.close()
    		sys.exit(1)


if __name__ == "__main__":
	s = Server()
	c = Client()
	threading.Thread(target = c.conn).start()
	threading.Thread(target = s.run).start()
