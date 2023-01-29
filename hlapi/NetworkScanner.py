# -*- coding: utf-8 -*-
'''
Copyright:	Schleifenbauer - 2019
Version:	1.1.5
Authors:	Laurent - laurent.schuermans@schleifenbauer.eu
			Schleifenbauer - support@schleifenbauer.eu

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

This software is provided "as is" and Schleifenbauer disclaims all warranties
with regard to this software including all implied warranties of merchantability
and fitness. In no event shall Schleifenbauer be liable for any special, direct,
indirect, or consequential damages or any damages whatsoever resulting from loss
of use, data or profits, whether in an action of contract, negligence or other
tortious action, arising out of or in connection with the use or performance of
this software.
'''

# System imports
import queue
import threading
import socket
import urllib
import re
import ipaddress
import time

# Library imports
from . library import requests

# Local imports
from . Helper import Helper as HLAPIHelper
from . DeviceManager import DeviceManager

class NetworkScanner():
	def __init__(self, hlapi_instance, input, http_port, webapi_user, dontUse=[]):
		self.hlapi = hlapi_instance
		self.input = input
		self.mode = None
		self.threads = round(self.hlapi.getConfig('max_threads')/2) # divide by 2 since each worker thread open 2 child threads (IPAPI & WEBAPI)

		# Connection variables
		self.http_port = http_port
		self.webapi_user = webapi_user
		self.dontUse = dontUse
		if self.hlapi.debug: print("The following protocols will be skipped due to invalid connection parameters:", dontUse)

		self.q = queue.Queue()
		self.result = []
		self.inputAccepted = True

		self.mode = HLAPIHelper.parseIP(self.input.replace('*', '0'))
		if self.hlapi.debug: print("Received", self.mode, "address")

		self.partial_ip = self.parseSubnet(self.input)
		self.progress = HLAPIHelper.createProgressManager(self.hlapi, name='NetworkScanner')

	# Remove '*' from subnet input
	def parseSubnet(self, ip):
		if self.mode == 'IPv4':
			return ip.replace('*', '')
		elif self.mode == 'IPv6':
			return ipaddress.ip_address(ip.replace('*', '')).exploded
		else:
			self.inputAccepted = False
			return None

	# Add all target IP addri to a queue and let x threads evaluate them.
	def startScan(self):
		self.progress.reset()
		if not self.inputAccepted:
			self.result = None
			self.progress.abort()
			return

		if "*" in self.input:
			self.result = []
			# Add IPv4 range to queue
			if self.mode == 'IPv4':
				self.progress.setTarget(254)
				for target in range(1, 255):
					self.q.put(self.partial_ip+str(target))

			# Add IPv6 range to queue, currently only the last group can be scanned
			elif self.mode == 'IPv6':
				pass
				# start = 0x0000
				# end = 0xFFFF
				# self.progress.setTarget(int(0xFFFF))
				# for target in range(start, end+1):
				#	append = hex(target).rstrip("L").lstrip("0x") or "0"
				#	self.q.put(self.partial_ip+str(append))


			# Start worker threads
			if self.hlapi.debug: print("Starting", self.threads, "threads for scanning of", self.mode, "subnet")
			for x in range(self.threads):
				t = threading.Thread(target=self.scanThread)
				self.progress.addThreadWatch(t)
				t.start()

		else:
			self.progress.setTarget(1)
			self.pollHost(self.input)
			self.progress.addProgress(1)

	# Aborts scanning, clear queue
	def abortScan(self):
		self.q.mutex.acquire()
		self.q.queue.clear()
		self.q.all_tasks_done.notify_all()
		self.q.unfinished_tasks = 0
		self.q.mutex.release()
		self.progress.abort()

	def getResult(self):
		return self.result

	# Adds an IP address to self.result if a connection to self.port or http can be established.
	def pollHost(self, target):
		if not self.progress.isAborted() or self.progress.isError():
			t_webapi = threading.Thread(target=self.WEBAPIThread, args=(target,))
			t_ipapi = threading.Thread(target=self.IPAPIThread, args=(target,))

			if not "WEBAPI" in self.dontUse:
				self.progress.addThreadWatch(t_webapi)
				t_webapi.start()
			if not "IPAPI" in self.dontUse:
				self.progress.addThreadWatch(t_ipapi)
				t_ipapi.start()

			while (t_webapi.isAlive() or t_ipapi.isAlive()) and not target in self.result:
				time.sleep(0.1)

	def IPAPIThread(self, target):
		if self.mode == 'IPv4':
			af = socket.AF_INET
		elif self.mode == 'IPv6':
			af = socket.AF_INET6

		s = socket.socket(af, socket.SOCK_STREAM)
		try:
			info = socket.getaddrinfo(target, self.hlapi.getConfig('ipapi_port'), af, socket.SOCK_STREAM)
			s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.settimeout(self.hlapi.getConfig('ipapi_timeout'))
			s.connect( info[0][4] )
			s.settimeout(0.0)
			if self.hlapi.debug: print(target, "IPAPI connection established")
			self.result.append(target)
			s.send(1)
			s.shutdown(socket.SHUT_RDWR)
		except:
			pass
		s.close()

	def WEBAPIThread(self, target):
		headers = {'Content-type': 'application/x-www-form-urlencoded'}
		url = 'http://'+str(target)+'/userid'
		try:
			stitched = b''
			response = requests.post(url, timeout=self.hlapi.getConfig('webapi_timeout'), headers=headers, stream=True, data={'user': self.webapi_user})
			httpcode = response.status_code
			if httpcode == 200:
				for chunk in response.iter_content(chunk_size=None):
					stitched += chunk
				data = urllib.parse.parse_qs(stitched.decode("utf-8"), True)
				if 'userid' in data.keys():
					if self.hlapi.debug: print(target, "WEBAPI connection established")
					if target not in self.result:
						self.result.append(target)
		except (requests.exceptions.RequestException, socket.error, socket.timeout) as e:
			pass

	# Worker thread, takes an IP from the queue and evaluates it.
	def scanThread(self):
		while self.progress.isRunning():
			try:
				current_target = self.q.get_nowait()
				while self.progress.isRunning():
					try:
						self.pollHost(current_target)
						break
					except Exception as e:
						if self.hlapi.debug: print("Too many open sockets, retry in one second...")
						print(e)
						time.sleep(1)
				if not self.progress.isAborted():
					self.q.task_done()
					self.progress.addProgress(1)
			except queue.Empty:
				pass
