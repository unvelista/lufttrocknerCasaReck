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
import sys
import subprocess
import signal
import os
import queue
import struct
import threading
import time
import re
import collections

# Local imports
from .. devices.AbstractDevice import AbstractDevice
from .. devices.Devices import *
from . ResetManager import ResetManager
from .. Helper import Helper as HLAPIHelper
from .. communication.Communicator import Communicator
from .. communication.IPAPIFramer import *
from .. communication.IPAPIProtocol import IPAPIProtocol

class FirmwareUpdate():
	def __init__(self, hlapi_instance):
		self.hlapi = hlapi_instance
		self.progress = HLAPIHelper.createProgressManager(self.hlapi, name='FirmwareUpdate')
		self.anti_sleep = None
		self.reset()

	def reset(self):
		self.progressMap = collections.OrderedDict()
		self.q = queue.Queue()
		self.progress.reset()

	def abortAll(self):
		for key, entry in self.progressMap.items():
			self.progressMap[key] = (entry[0], 'Aborted', entry[2])
		t = threading.Thread(target=self.abortAllThreads, args=())
		t.daemon = True
		t.start()

	def abortAllThreads(self):
		self.q.mutex.acquire()
		self.q.queue.clear()
		self.q.all_tasks_done.notify_all()
		self.q.unfinished_tasks = 0
		self.q.mutex.release()
		if self.anti_sleep is not None:
			try:
				os.killpg(os.getpgid(self.anti_sleep.pid), signal.SIGTERM)
				if self.hlapi.debug: print("Caffeinate terminated")
			except:
				if self.hlapi.debug: print("Error: could not terminate caffeinate")
		if self.hlapi.debug: print("Closing threads...")
		self.progress.abort()
		self.progress.closeThreads()

	# binpath can be a single .bin path for multiple devices or a dictionary of bin paths per device hardware id
	def startFirmwareUpgrade(self, scheme):
		self.reset()
		max_threads = self.hlapi.getConfig('max_threads') - 1

		if 'darwin' in sys.platform:
			if self.hlapi.debug: print("System is darwin, launching caffeinate")
			self.anti_sleep = subprocess.Popen('caffeinate', stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

		# Init progress map
		for ip, data in scheme.items():
			for deviceDict in data['devices']:
				self.progress.addTarget(1)
				if deviceDict['args']['broadcast']:
					ipstr = deviceDict['device'].ip
				else:
					ipstr = deviceDict['device'].getUid()
				self.setProgress(ipstr, deviceDict['args']['fw'][0], 'Queued', 0)
			self.q.put( data )

		# Return False if addTarget has not been called
		if self.progress.state == None:
			return False

		# Start worker threads
		for x in range(min(len(scheme.keys()), max_threads)):
			t = threading.Thread(target=self.firmwareUpgrade, args=[x, self.q, data])
			self.progress.addThreadWatch(t)
			t.start()

		return True

	def setProgress(self, uid, version, status, percentage):
		label = uid+'@'+str(version)
		if label in self.progressMap and self.progressMap[label][1] == 'Aborted':
			return
		self.progressMap[label] = (version, status, percentage)

	def firmwareUpgrade(self, tid, q, data):
		regex = '^(?P<oem>SP|MK)FW-(?P<version>\d{4})-(?P<checksum>[0-9A-F]{8})-(?P<crc>[0-9A-F]{4}).(?P<extra>.*)\.bin$'
		while self.progress.isRunning():
			try:
				interfaceData = q.get_nowait()
			except queue.Empty:
				time.sleep(1)
				continue
			if self.hlapi.debug: print("Thread", tid, "received interface task")

			# All communicators in bundle are the same
			communicator = interfaceData['devices'][0]['device'].communicator
			ipapi = communicator.getProtocol('IPAPI')
			if ipapi is not None and ipapi.conn:
				for deviceDict in interfaceData['devices']:
					if not self.progress.isRunning():
						break

					device = deviceDict['device']
					args = deviceDict['args']

					if args['broadcast']:
						currentID = device.ip
					else:
						currentID = device.getUid()

					version = args['fw'][0]
					path = args['fw'][2]

					self.setProgress(currentID, version, 'Preparing', 0)
					if self.hlapi.debug: print(str(tid)+":", "Upgrading", currentID, "to", str(version), "with parameters:", args)

					filename = os.path.basename(path)
					match = re.match(regex, filename, re.IGNORECASE)
					if not match:
						if self.hlapi.debug: print(tid, 'Invalid filename')
						break
					groups = match.groupdict()
					file_version = int(groups['version'], base=10)
					file_checksum = int(groups['checksum'], base=16)
					file_crc = int(groups['crc'], base=16)

					# Split binary file into blocks of size 256
					blocks = []
					bytesize = 0
					with open(path, mode='rb') as binf:
						while True:
							block = binf.read(256)
							if block: # will be empty string (thus False) if EOF reached
								blocks.append(block)
								bytesize += len(block)
							else:
								break
					num_blocks = len(blocks)

					# Write firmware info to 'upvers' register (10000)
					# [version][checksum][crc][numberOfBlocks][size]
					#
					# < = little-endian
					# H = unsigned short integer size 2
					# L = unsigned long integer size 4
					fw_info = struct.pack('<HLHHL', file_version, file_checksum, file_crc, num_blocks, bytesize)

					# Delay can be reduced to about 0.1 for non-ringmaster devices that are directly addressable (ethernet, no databus)
					# however, the hPDU mode cannot be read through the IPAPI making it impossible to determine whether the device
					# is behind a gateway or another hPDU...
					delay = 0.3

					# Since each thread handles a bundle of devices using the same communicator,
					# we can only fast-update if the bundle contains a single device (no databus)
					if device.isHybridMaster():
						delay = 0.1

					if self.hlapi.debug: print(tid, "Packet delay set to", delay)

					f = Frame()
					if args['broadcast']:
						# Reboot devices before firmware updating to prevent PDU getting stuck at 'RETRY'.
						rsManager = ResetManager(self.hlapi, device)
						rsManager.reboot(resetComm=True, broadcast=True)
						ipapi._flushSocket()
						# Send 3 dummy bytes so a gateway gives us the full socket without yielding.
						for x in range(3, 0, -1):
							if self.hlapi.debug: print(tid, "Dummy broadcast "+str(x))
							d = Frame()
							d.Fields = BroadcastWriteRegisterFields
							d.setField(COMMAND, d.CMD_BRWRITE[0])
							d.setField(REGISTERSTART, 10000)
							d.setField(REGISTERLENGTH, 14)
							d.setField(DATA, struct.pack('<HLHHL', 0, file_checksum, file_crc, x, 3))
							writer = ipapi.writeRaw(d)
							time.sleep(delay)

						f.Fields = BroadcastWriteRegisterFields
						f.setField(COMMAND, f.CMD_BRWRITE[0])
					else:
						f.Fields = WriteRegisterFields
						f.setField(COMMAND, f.CMD_WRITE[0])
						f.setField(UNITADDRESS, device.unitAddress)

					f.setField(REGISTERSTART, 10000)
					f.setField(REGISTERLENGTH, 14)
					f.setField(DATA, fw_info)

					if 'deep' in args and args['deep'] is True:
						writeRepeats = 3
					else:
						writeRepeats = 1
					last_block_hold = writeRepeats-1

					self.setProgress(currentID, version, 'Writing header', 0)
					if self.hlapi.debug: print(tid, "Writing header:", file_version, file_checksum, file_crc, num_blocks, bytesize)

					# Temporarily increase IPAPI timeout
					backupIPAPITimeout = ipapi.timeout
					ipapi.timeout = 15
					if self.hlapi.debug: print(tid, 'Increased IPAPI timeout')

					for x in range(3):
						writer = ipapi.writeRaw(f)
						time.sleep(1)

					self.setProgress(currentID, version, 'Erasing flash', 0)

					# PDU Erase flash
					time.sleep(14)

					# Now that we have aquired a lock on the end device socket, temporarily disable API yielding.
					backupIPAPIYieldSeconds = ipapi.yieldSeconds
					ipapi.yieldSeconds = 0
					if self.hlapi.debug: print(tid, 'Disabled IPAPI yielding')

					# Write blocks to 'upblnr' (10100) register
					# [dataBlockNumber][dataBlock]
					# Each block write requires an updated block number (size 2) and data (size 256)
					if self.hlapi.debug: print(tid, 'Writing blocks...')
					if self.hlapi.debug: print(tid, 'ETA:', int(num_blocks)*writeRepeats*delay+30, 'seconds')
					# gen 1 broadcast ± minutes
					# gen 1 broadcast deep update ± minutes
					# gen 2/3 broadcast ±10 minutes
					# gen 2/3 deep update broadcast ±27 minutes
					# gen 2/3 direct ±3 minutes

					# The next three loops are in place to ensure packets being sent as 123123123 instead of 111222333
					for i in range(0, num_blocks, writeRepeats):
						if not self.progress.isRunning() or not ipapi.conn:
							break
						for x in range(writeRepeats):
							if not self.progress.isRunning() or not ipapi.conn:
								break
							for y in range(writeRepeats):
								if not self.progress.isRunning() or not ipapi.conn:
									break

								currentBlock = i+y

								# Skip out of range blocks
								if currentBlock > num_blocks-1:
									continue

								# Current block data
								block = blocks[currentBlock]
								# < = Little-endian
								# H = unsigned short integer size 2
								# s = char[] string (256 bytes)
								data = struct.pack('<H256s', currentBlock, block)

								# Same reason as dummy header writes, we need to re-aquire the lock on a gateway's socket.
								if i == 0 and x == 0: # first 3 writes
									time.sleep(1)

								# Prepare frame
								f = Frame()
								if args['broadcast']:
									f.Fields = BroadcastWriteRegisterFields
									f.setField(COMMAND, f.CMD_BRWRITE[0])
								else:
									f.Fields = WriteRegisterFields
									f.setField(COMMAND, f.CMD_WRITE[0])
									f.setField(UNITADDRESS, device.unitAddress)

								f.setField(REGISTERSTART, 10100)
								f.setField(REGISTERLENGTH, 258)
								f.setField(DATA, data)

								time_start = time.time()

								# Rewrite last packet because classic PDUs behind a bridged device have no patience
								if currentBlock == num_blocks-1:
									if last_block_hold == 0:
										# Quick fix for PDU queue deadlock bug
										time.sleep(6)
										for z in range(writeRepeats):
											ipapi.writeRaw(f)
											time.sleep(delay)
									else:
										last_block_hold -= 1
										continue
								else:
									# Send frame
									if (currentBlock+1) % 100 == 0:
										if self.hlapi.debug: print(tid, 'Writing block', currentBlock+1, "of", num_blocks)

									writer = ipapi.writeRaw(f)
									if writer is not True:
										if self.hlapi.debug: print("BLOCK", writer)

								noSleep = False

								if not args['broadcast']:
									# Block until ACK received to prevent multiple packets on databus at the same time
									# The gateway will expect classic PDUs to return ACK but they will return a timeout
									# error code for each sent block.
									if not isinstance(device, cPDU):
										response = ipapi.readRaw()
										if response is None or response == 'TIMEOUT':
											if self.hlapi.debug: print("No response")
										else:
											noSleep = True

								# Prevent percentage from going down
								if x == 0 and y == 0:
									self.setProgress(currentID, version, 'Writing FW', int(currentBlock/(num_blocks-1)*100))

								sleepTime = 0
								# The first few blocks are sent with a longer delay
								if i == 0 and x == 0:
									sleepTime = 1

								# Calculate total time from block write to now (repeats, delays, response)
								# and sleep if time is less than expected
								time_elapsed = time.time()-time_start

								if not noSleep and time_elapsed < delay:
									sleep = max(sleepTime, delay-time_elapsed) # either 0, 1 or delay-time_elapsed
									time.sleep(sleep)

					if not ipapi.conn:
						self.setProgress(currentID, version, 'IPAPI error', 0)
					elif not (self.progress.isAborted() or self.progress.isError()):
						if self.hlapi.debug: print(tid, 'Verify...')
						self.setProgress(currentID, version, 'FW verification', 100)

						# PDU Verify firmware
						time.sleep(20)

						if self.hlapi.debug: print(tid, 'Rebooting...')
						self.setProgress(currentID, version, 'Rebooting', 100)

						# Reboot devices and reset communicator
						rsManager = ResetManager(self.hlapi, device)
						rsManager.reboot(resetComm=True, broadcast=True)

						if not args['broadcast']:
							# Check if device has flashed to new firmware
							newfw = device.read('idfwvs', 'single', cache=False)
							if newfw is not None:
								idfwvs = newfw.get('idfwvs', None)
								if idfwvs == version:
									if self.hlapi.debug: print(tid, 'Success')
									self.setProgress(currentID, version, 'Success', 100)
								else:
									if self.hlapi.debug: print(tid, 'Fail?')
									self.setProgress(currentID, version, 'Update or reboot failed', 100)
							else:
								self.setProgress(currentID, version, 'Unknown', 100)
						else:
							self.setProgress(currentID, version, 'Done', 100)

					# Allow DWriteResult to update state based on self.progressMap before !isRunning()
					time.sleep(3)

					# Restore API yielding
					ipapi.yieldSeconds = backupIPAPIYieldSeconds
					if self.hlapi.debug: print(tid, 'IPAPI yielding restored')
					# Restore API timeout
					ipapi.timeout = backupIPAPITimeout
					if self.hlapi.debug: print(tid, 'IPAPI timeout restored')

					self.progress.addProgress(1)
			else:
				for deviceDict in interfaceData['devices']:
					device = deviceDict['device']
					args = deviceDict['args']
					if args['broadcast']:
						currentID = device.ip
					else:
						currentID = device.getUid()
					version = args['fw'][0]
					self.setProgress(currentID, version, 'Error: No IPAPI', 0)
					self.progress.addProgress(1)

			if not (self.progress.isAborted() or self.progress.isError()):
				q.task_done()
