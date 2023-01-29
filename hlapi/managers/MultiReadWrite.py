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
import threading
import queue
from collections import OrderedDict

# Local imports
from .. Helper import Helper as HLAPIHelper
from .. spdm.RegisterHelper import RegisterHelper
from .. spdm.Registers import *

# MultiReadWrite class, each high level manager inherits this class
#
class MultiReadWrite(object):
	# Set self.devices to a list of device instances
	def __init__(self, hlapi_instance, devices, progress=None):
		self.hlapi = hlapi_instance
		if isinstance(devices, list):
			self.devices = devices
		else:
			self.devices = [devices]

		self.result = None

		if progress is None:
			self.progress = HLAPIHelper.createProgressManager(self.hlapi, name='MultiReadWrite')
		else:
			self.progress = progress

	def readSingle(self, mnemonic):
		result = self.readAll([mnemonic])
		# We know each UID only has one value (single register)
		for key, value in result.items():
			result[key]['data'] = HLAPIHelper.extract(value['data'])
		return result

	# Wrapper function for HLAPI consistency
	def startReadAll(self, mnemonics):
		self.readAll(mnemonics, block=False)

	def readAll(self, mnemonics, block=True):
		self.result = {}
		self.progress.reset()

		bundled = HLAPIHelper.bundleDevicesByCommunicator(self.devices)
		if self.hlapi.debug: print("Starting", len(bundled), "threads for mass read of", len(mnemonics), "registers on", len(self.devices), "devices.")
		self.progress.setTarget(len(mnemonics) * len(self.devices))

		worker_queue = queue.Queue()
		for bundle in bundled:
			worker_queue.put(bundle)

		max_threads = self.hlapi.getConfig('max_threads')
		for i in range(min(len(bundled), max_threads)):
			t = threading.Thread(target=self._readThread, args=[worker_queue, mnemonics])
			self.progress.addThreadWatch(t)
			t.start()

		if block:
			self.progress.closeThreads()
			return HLAPIHelper.makeOrdered(self.result)

	def _readThread(self, q, mnemonics):
		while self.progress.isRunning():
			try:
				devices = q.get_nowait()
			except queue.Empty:
				return

			for device in devices:
				self.result[device.getUid()] = {
					'device': device,
					'data': {}
				}
				for mnemonic in mnemonics:
					if self.progress.isAborted() or self.progress.isError():
						q.mutex.acquire()
						q.queue.clear()
						q.all_tasks_done.notify_all()
						q.unfinished_tasks = 0
						q.mutex.release()
						return
					data = device.read(mnemonic, 'single', extract=True)
					self.result[device.getUid()]['data'][mnemonic] = data
					self.progress.addProgress(1)
			q.task_done()

	def writeSingle(self, mnemonic, data):
		dataMap = {}
		for device in self.devices:
			dataMap[device.getUid()] = {'device': device, 'data': {mnemonic: data}}
		result = self.writeAll(dataMap)
		# We know each UID only has one value (single register)
		for key, value in result.items():
			result[key]['data'] = HLAPIHelper.extract(value['data'])
		return result

	# Wrapper function for HLAPI consistency
	def startWriteAll(self, dataMap):
		self.writeAll(dataMap, block=False)

	# dataMap: {UID: {mnemonic:value, mnemonic:value}, UID: {mnemonic:value, mnemonic:value}, etc.}
	def writeAll(self, dataMap, block=True):
		self.result = {}
		self.progress.reset()

		bundled = HLAPIHelper.bundleDevicesByCommunicator(self.devices)
		if self.hlapi.debug: print("Starting", len(bundled), "threads for mass write on", len(self.devices), "devices.")

		num_writes = 0
		for uid, values in dataMap.items():
			num_writes += len(values.keys())
		self.progress.setTarget(num_writes)

		worker_queue = queue.Queue()
		for bundle in bundled:
			worker_queue.put(bundle)

		max_threads = self.hlapi.getConfig('max_threads')
		for i in range(min(len(bundled), max_threads)):
			t = threading.Thread(target=self._writeThread, args=[worker_queue, dataMap])
			self.progress.addThreadWatch(t)
			t.start()

		if block:
			self.progress.closeThreads()
			return HLAPIHelper.makeOrdered(self.result)

	# Same interface devices in a list
	def _writeThread(self, q, dataMap):
		while self.progress.isRunning():
			try:
				devices = q.get_nowait()
			except queue.Empty:
				return

			for device in devices:
				oldUid = device.getUid()
				dataMapEntry = dataMap.get(oldUid, {})

				for mnemonic, value in dataMapEntry.items():
					if self.progress.isAborted() or self.progress.isError():
						q.mutex.acquire()
						q.queue.clear()
						q.all_tasks_done.notify_all()
						q.unfinished_tasks = 0
						q.mutex.release()
						return

					data = device.write(mnemonic, 'single', value)
					if data is not None:
						status = data
					else:
						status = False

					deviceUid = device.getUid()

					# Device address has been changed
					if oldUid != deviceUid and oldUid in self.result:
						# Copy old UID result to new UID result
						oldUidResult = self.result[oldUid]
						self.result[deviceUid] = oldUidResult
						del self.result[oldUid]

					if not deviceUid in self.result:
						self.result[deviceUid] = {'device': device, 'data': {}}

					self.result[deviceUid]['data'][mnemonic] = status
					self.progress.addProgress(1)
			q.task_done()

	@staticmethod
	def validateWrite(scheme, deviceManager): # {UID: {'device': Device, 'data': {mnemomic: value}}}
		result = OrderedDict()

		# Iterate interfaces
		for uid, values in scheme.items():
			device = values['device']
			register_data = values['data']

			result[uid] = {
				'device': device,
				'data': OrderedDict(),
				'not_writable': []
			}

			# Check if new unit address is not duplicate in ring
			if 'idaddr' in register_data.keys():
				newAddr = register_data.get('idaddr')
				allDevices = deviceManager.getResult()
				devicesInRing = allDevices.get(device.ip, {}).get('devices', [])
				unitsInRing = [x.get('device').unitAddress for x in devicesInRing]
				if newAddr not in unitsInRing:
					if RegisterHelper.isValidUnitAddress(newAddr):
						result[uid]['data']['idaddr'] = newAddr
					else:
						result[uid]['not_writable'].append(('unitAddress', 'invalid input'))
				else:
					result[uid]['not_writable'].append(('unitAddress', 'address already exists'))
				del register_data['idaddr']

			# Prioritize outlet unlock
			if 'swounl' in register_data.keys():
				unlState = register_data.get('swounl')
				if str(unlState).lower() != 'none' and len(str(unlState)) > 0:
					result[uid]['data']['swounl'] = unlState
				else:
					result[uid]['not_writable'].append(('unlock', 'invalid input'))
				del register_data['swounl']

			# Handle username / password change
			if 'usname' in register_data.keys() and 'uspaswd' in register_data.keys():
				result[uid]['data']['login'] = list(zip(register_data['usname'], register_data['uspaswd']))
				del register_data['usname']
				del register_data['uspaswd']

			# Iterate write registers and values
			for mnemonic, value in HLAPIHelper.orderDictByMnemonics(register_data).items():
				register = RegisterHelper.registerLookup(mnemonic)

				if register is None:
					result[uid]['not_writable'].append((register.Name, 'unknown register'))
					continue

				canwrite = device.canWriteRegister(register)
				if canwrite is not True:
					result[uid]['not_writable'].append((register.Name, canwrite))
					continue

				if isinstance(value, list):
					filtered = []
					# Pass when all values in list are None
					if all([str(v).lower() == 'none' for v in value]):
						result[uid]['not_writable'].append((register.Name, 'input empty'))
						continue
					else:
						for v in value:
							if str(v).lower() != 'none':
								filtered.append(v)
							else:
								# None value in a list of register repeats
								if register.Type == ASCII or register.Type == IPV4:
									filtered.append('')
								elif register.Type == INT:
									filtered.append(0)
								elif register.Type == FD:
									filtered.append(0.0)
						value = filtered
				elif str(value).lower() == 'none':
					result[uid]['not_writable'].append((register.Name, 'input empty'))
					continue

				if mnemonic == 'login':
					result[uid]['data'][mnemonic] = value
					continue

				canwrite = RegisterHelper.checkWriteInput(register, value, device=device)
				if canwrite is not True:
					result[uid]['not_writable'].append((register.Name, canwrite))
					continue

				result[uid]['data'][mnemonic] = value

		return result
