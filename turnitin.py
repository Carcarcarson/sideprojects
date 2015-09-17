"""
turnitin.py 
Easily move files from your computer to the CS servers. 
python turnitin.py -f /path/2/file

Required things: python 2.7, and the follow packages: argparse, scp, paramiko
Run as superuser 

Carson Harmon, harmon35@purdue.edu
"""
#for the ssh handle
import paramiko 
#grab file input path easily 
import argparse
#to hide the password characters
import getpass
#for scp 
from scp import SCPClient


#argparse block to grab stdin 

parser = argparse.ArgumentParser()
parser.add_argument("-f", metavar="f", help="File path")
args = parser.parse_args()


#define target host and port
cs_server = "128.10.12.13"
sshport = 22

#create ssh object. 
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())


#user credientals 
user = raw_input("What is your career account username?  ")
print "You won't see the characters as you type in your password, but its working I swear"
pswd = getpass.getpass("Password: ")

#start ssh session
ssh.connect(cs_server, username=user, password=pswd, allow_agent=False, look_for_keys=False)

#SCP files
scp = SCPClient(ssh.get_transport())
scp.put(args.f, "/homes/" + user)

