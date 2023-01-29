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
import collections
import hashlib
import re
import os
import time
from collections import OrderedDict

# Local imports
from . spdm.RegisterHelper import RegisterHelper

class Helper():
	REG_IPV4 = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
	REG_IPV6 = re.compile('^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)$')

	@staticmethod
	def sortUIDs(uids):
		ips = []
		units = []
		for uid in uids:
			ip, unit = uid.split('#')
			ips.append(tuple(int(x) for x in ip.split('.')))
			units.append(int(unit))
		if len(uids) > 0:
			ips, units = (list(t) for t in zip(*sorted(zip(ips, units))))
		result = []
		for i in range(len(ips)):
			result.append(".".join(str(x) for x in ips[i])+'#'+str(units[i]))
		return result

	@staticmethod
	def sortMnemonics(mnemonics):
		registers = [RegisterHelper.registerLookup(x) for x in mnemonics]
		registers.sort(key=lambda x: x.RegisterStart)
		sortedMnemonics = [x.Mnemonic for x in registers]
		return sortedMnemonics

	@staticmethod
	def orderDictByUIDs(unordered):
		ordered = collections.OrderedDict()
		keys = unordered.keys()
		orderedKeys = Helper.sortUIDs(keys)
		for key in orderedKeys:
			ordered[key] = unordered[key]
		return ordered

	@staticmethod
	def orderDictByMnemonics(unordered):
		ordered = collections.OrderedDict()
		keys = unordered.keys()
		orderedKeys = Helper.sortMnemonics(keys)
		for key in orderedKeys:
			ordered[key] = unordered[key]
		return ordered

	@staticmethod
	def makeOrdered(normalDict):
		for uid, values in normalDict.items():
			mnemonics = values['data']
			try:
				normalDict[uid]['data'] = Helper.orderDictByMnemonics(mnemonics)
			except:
				pass
		result = Helper.orderDictByUIDs(normalDict)
		return result

	# Returns MD5 checksum of a given file
	@staticmethod
	def fileMD5(path):
		return str(hashlib.md5(open(path, 'rb').read()).hexdigest())

	@staticmethod
	def parseFirmwareFile(path):
		filename = os.path.basename(path)
		regex = '^(?P<oem>SP|MK)FW-(?P<version>\d{4})-(?P<checksum>[0-9A-F]{8})-(?P<crc>[0-9A-F]{4}).(?P<extra>.*)\.bin$'
		match = re.match(regex, filename, re.IGNORECASE)
		# oem, version, checksum, crc, extra
		if match:
			groups = match.groupdict()
			file_version = int(groups['version'], base=10)
			file_extra = str(groups['extra'])
			return [file_version, file_extra, path]

		return None

	@staticmethod
	def latestFWVersion(firmwares):
		if len(firmwares) == 0:
			return None
		# Select maximum internal FW version
		maxFW = (0, 0)
		for fw in firmwares:
			if fw[0] > maxFW[0]:
				maxFW = fw
			elif fw[0] == maxFW[0]:
				try:
					max_fw_pl_num = int(maxFW[1].split('PL')[1])
					cur_fw_pl_num = int(fw[1].split('PL')[1])
					if cur_fw_pl_num > max_fw_pl_num:
						maxFW = fw
				except:
					pass

		return maxFW

	# The new structure, dictionary, each entry contains all devices in an interface
	# and each interface or device has their own individual paramters
	@staticmethod
	def generateInterfaceDict(devices):
		bundled = Helper.bundleDevicesByCommunicator(devices)
		bundled.sort(key=lambda x: x[0].ip)
		for interface in bundled:
			interface.sort(key=lambda x: x.unitAddress)

		result = collections.OrderedDict()
		for bundle in bundled:
			# Create [{'device': Device, 'args': {}}, {'device': Device, 'args': {}}, {'device': Device, 'args': {}}, ...]
			devices = []
			for device in bundle:
				device_with_args = {'device': device, 'args': {}}
				devices.append(device_with_args)

			firstInBundle = bundle[0]
			if not firstInBundle.ip in result:
				result[firstInBundle.ip] = {'devices': devices, 'args': {}}
		return result

	# Converts a list of devices to a list of lists where each sublist contains devices using the same communicator
	# This means that reach result list contains devices behing the same IP:PORT combination.
	@staticmethod
	def bundleDevicesByCommunicator(devices):
		result = []
		bundledDevices = []
		for device_i in devices:
			if device_i is not None and device_i not in bundledDevices:
				i_bundle = []
				communicator = device_i.communicator
				for device_j in devices:
					if device_j is not None and device_i.ip == device_j.ip:
						i_bundle.append(device_j)
						bundledDevices.append(device_j)
				result.append(i_bundle)
		return result

	# Some regex magic for removing control characters from a string
	all_chars = (chr(i) for i in range(0x110000))
	control_chars = ''.join(map(chr, list(range(0,32)) + list(range(127,160))))
	control_char_re = re.compile('[%s]' % re.escape(control_chars))

	# Removes unprintable characters from a string
	@staticmethod
	def removeControlChars(s):
		return Helper.control_char_re.sub('', s)

	# Recursive dictionary merge
	@staticmethod
	def dictMerge(x, y):
		if isinstance(x, OrderedDict) or isinstance(y, OrderedDict):
			return OrderedDict({**x, **y})
		else:
			return {**x, **y}

	# Convenience method for extracting values from a list or dict
	# Input: list, dict or anything else
	# Ouput: single value if input is single element list or dict, list of values if input is dict
	@staticmethod
	def extract(data):
		if isinstance(data, dict):
			values = list(data.values())
			if len(values) == 1:
				return values[0]
			else:
				return values
		elif isinstance(data, list):
			if len(data) == 1:
				return data[0]
			else:
				return data
		return data

	@staticmethod
	def firmwareToGeneration(firmware):
		try:
			firmware = int(firmware)
		except:
			return None
		return 'hybrid' if int(firmware) > 200 else 'classic'

	@staticmethod
	def deviceToType(device):
		from . devices.Devices import cPDU
		from . devices.Devices import hPDU
		from . devices.Devices import hPDU_G3
		from . devices.Devices import DPM27
		from . devices.Devices import DPM27e
		from . devices.Devices import DPM3
		from . devices.Devices import Gateway

		if isinstance(device, cPDU):
			return 'cpdu'
		elif isinstance(device, hPDU):
			return 'hpdu'
		elif isinstance(device, hPDU_G3):
			return 'hpdu_g3'
		elif isinstance(device, DPM27):
			return 'dpm27'
		elif isinstance(device, DPM27e):
			return 'dpm27e'
		elif isinstance(device, DPM3):
			return 'dpm3'
		elif isinstance(device, Gateway):
			return 'gateway'
		else:
			return 'abstract'

	@staticmethod
	def hpduModeName(hpdu_mode):
		if hpdu_mode == 0:
			return 'Classic'
		elif hpdu_mode == 5:
			return 'Hybrid'
		elif hpdu_mode == 7:
			return 'Bridge'
		elif hpdu_mode == 13:
			return 'Colo-infra'
		elif hpdu_mode == 21:
			return 'Colo-enduser'
		elif hpdu_mode == 27:
			return 'Twin master'
		else:
			return None

	@staticmethod
	def organizeInterfaces(interfaces):
		result = {}
		for key, value in interfaces.items():
			# Check if key is IP/SUBNET/direct
			if "*" in key:
				# SUBNET
				# Look for IPs/Direct already in result and remove
				keys_to_remove = []
				for rkey, rvalue in result.items():
					if key.split('*')[0] in rkey:
						keys_to_remove.append(rkey)
				for rkey in keys_to_remove:
					del result[rkey]
				result[key] = value # override possible DIRECT entry, IP/SUBNET will be scanned anyway
			elif not "#" in key:
				# IP
				subnet = Helper.ipToSubnet(key) # convert IP to subnet range
				if subnet is None or not subnet in result:
					# Look for Direct already in result and remove
					keys_to_remove = []
					for rkey, rvalue in result.items():
						if key in rkey:
							keys_to_remove.append(rkey)
					for rkey in keys_to_remove:
						del result[rkey]
					result[key] = value
			else:
				# DIRECT
				uid = key.split("#")
				subnet = Helper.ipToSubnet(uid[0])
				if not key in result and not uid[0] in result and (subnet is None or not subnet in result):
					result[key] = value

		return result

	@staticmethod
	def subnetsToIPs(interfaces, ips):
		subnets = {}
		for ip in ips:
			subnet = Helper.ipToSubnet(ip)
			parameters = None
			if not subnet in subnets:
				if subnet in interfaces:
					subnets[subnet] = interfaces[subnet]
					parameters = subnets[subnet]
					del interfaces[subnet]
				else:
					parameters = interfaces[ip]
			else:
				parameters = subnets[subnet]
			if not ip in interfaces:
				interfaces[ip] = parameters

		return interfaces

	@staticmethod
	def parseIP(ip):
		if len(re.findall(Helper.REG_IPV4, ip)) == 1:
			return 'IPv4'
		elif len(re.findall(Helper.REG_IPV6, ip)) == 1:
			return 'IPv6'
		else:
			return None

	@staticmethod
	def ipToSubnet(ip):
		if len(re.findall(Helper.REG_IPV4, ip)) == 1:
			return ".".join(ip.split('.')[:-1])+".*"
		else:
			return None

	@staticmethod
	def createProgressManager(hlapi_instance, name='untitled', runState='run', endState='done', abortState='abort', errState='error', explicitFinish=False):
		return ProgressManager(hlapi_instance, name, runState, endState, abortState, errState, explicitFinish)

class ProgressManager():
	def __init__(self, hlapi_instance, name, runState, endState, abortState, errState, explicitFinish):
		self.hlapi = hlapi_instance
		self.name = name
		self.runState = runState
		self.endState = endState
		self.abortState = abortState
		self.errState = errState

		self.explicitFinish = explicitFinish

		self.finished = None
		self.progress = None
		self.target = None
		self.state = None

		self.children = []
		self.threadsToWaitFor = []

	def reset(self):
		if len(self.threadsToWaitFor) > 0:
			if self.hlapi.debug: print("ProgressManager", self.name, "received reset command before", len(self.threadsToWaitFor), "child threads finished!")
		self.progress = None
		self.target = None
		self.state = None
		if self.explicitFinish:
			self.finished = False
		self.children = []

	def setTarget(self, target):
		if target > 0:
			self.target = target
			self.progress = 0
			self.setState(self.runState)
		elif target == 0:
			if self.hlapi.debug: print("ProgressManager", self.name, "got target equal to 0 (setTarget). Finishing...")
			self.setState(self.endState)
		else:
			if self.hlapi.debug: print("ProgressManager", self.name, "got target less than 0 (setTarget). Status:", self.getStatus())
			self.setState(self.errState)

	def setState(self, state):
		self.state = state
		if self.hlapi.debug: print("ProgressManager", self.name, "state changed:", self.getStatus())

	def getStatus(self):
		if self.state is None or self.progress is None or self.target is None:
			return None

		p_total = self.progress
		t_total = self.target

		for child in self.children:
			s = child.getStatus()
			if s is not None:
				p_total += s[2]
				t_total += s[3]

		percentage = int((p_total/t_total)*100)
		if self.explicitFinish:
			percentage = 99

		return (self.state, percentage, p_total, t_total)

	def setProgress(self, progress):
		if self.isRunning():
			if progress >= 0 and progress <= self.target:
				self.progress = progress
				if self.progress == self.target:
					self.setState(self.endState)
			else:
				if self.hlapi.debug: print("ProgressManager", self.name, "got progress value < 0 or greater than target (setProgress). Status:", self.getStatus())
				self.setState(self.errState)

	def addProgress(self, progress):
		if self.isRunning():
			if progress >= 0 and self.progress+progress <= self.target:
				self.setProgress(self.progress+progress)
			else:
				if self.hlapi.debug: print("ProgressManager", self.name, "got progress value < 0 or greater than target (addProgress). Status:", self.getStatus())
				self.setState(self.errState)

	def addTarget(self, target):
		if not self.isRunning():
			self.setTarget(target)
		else:
			if target >= 0:
				self.target += target
			else:
				if self.hlapi.debug: print("ProgressManager", self.name, "got target less than 0 (addTarget). Status:", self.getStatus())
				self.setState(self.errState)

	def abort(self, error=None):
		if error is None:
			self.setState(self.abortState)
		else:
			self.errState = error
			self.setState(self.errState)
		for child in self.children:
			child.abort(error=error)

	def isRunning(self):
		return (self.state is not None and not self.isDone() and not self.isAborted() and not self.isError())

	def isAborted(self):
		return (self.state == self.abortState)

	def isDone(self):
		done = (self.state == self.endState)
		allowed = not self.explicitFinish or (self.explicitFinish and self.finished)
		for child in self.children:
			if not child.isDone():
				return False
		return done and allowed

	def isError(self):
		return (self.state == self.errState)

	def finish(self):
		if not self.explicitFinish:
			self.setState(self.errState)
		elif self.progress != self.target:
			if self.hlapi.debug: print("ProgressManager", self.name, "received finish call before target reached!")
			self.setState(self.errState)
		else:
			self.finished = True
			self.setState(self.endState)

	def forceFinish(self):
		if self.explicitFinish:
			self.finished = True
		self.setState(self.endState)

	def waitForInit(self):
		for child in self.children:
			child.waitForInit()
		while self.state == None:
			time.sleep(0.5)
			if self.isAborted() or self.isError():
				break

	def addThreadWatch(self, t):
		self.threadsToWaitFor.append(t)

	def addChildProgress(self, progressManager):
		if progressManager not in self.children:
			self.children.append(progressManager)

	def closeThreads(self):
		if len(self.threadsToWaitFor) == 0:
			return
		for t in self.threadsToWaitFor:
			if t.is_alive():
				t.join()
		self.threadsToWaitFor = []
		for child in self.children:
			child.closeThreads()
