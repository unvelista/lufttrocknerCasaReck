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
import json
import queue
import threading
import time
from copy import deepcopy

# Library imports
from . library.dict2xml import dict2xml

# Local imports
from . Helper import Helper as HLAPIHelper
from . devices.AbstractDevice import AbstractDevice
from . devices.Devices import *

# DeviceManager class
#
# Device manager, capable of turning a list of IP addresses into device objects.
#
class DeviceManager(object):
	# Turns a list of IPs and specific devices into a dict of specific device objects
	def __init__(self, hlapi_instance):
		self.hlapi = hlapi_instance
		self.devices = []
		self.unknownDevices = []
		self.updatedDevices = 0
		self.progress = HLAPIHelper.createProgressManager(self.hlapi, name='DeviceManager', explicitFinish=True)
		self.result = None

	def reset(self):
		self.abort()
		self.unknownDevices = []
		self.updatedDevices = 0
		self.devices = []
		self.identifyPool = {}
		self.progress.reset()
		self.result = None

	def clearUnknownDevices(self):
		self.unknownDevices = []

	def clearUpdatedDevices(self):
		self.updatedDevices = 0

	def abort(self):
		if not (self.progress.isAborted() or self.progress.isError()):
			if self.hlapi.debug: print("Aborting DeviceManager")
			self.progress.abort()
		else:
			if self.hlapi.debug: print("Could not abort DeviceManager: not running")
		self.progress.closeThreads()

	def startLoadInterfaces(self, targets):
		if self.hlapi.debug: print("Starting IP identification for", len(targets), "targets")
		self.progress.reset()
		t = threading.Thread(target=self.loadInterfaces, args=[targets])
		t.start()

	def startLoadFile(self, path, graphPath=None):
		# return file graph checksum
		# return number of devices added
		if self.hlapi.debug: print("Starting file load from", path, ", checking for graph at", graphPath)
		self.progress.reset()
		t = threading.Thread(target=self.loadFile, args=[path], kwargs={'graphPath':graphPath})
		self.progress.addThreadWatch(t)
		t.start()

	def loadInterfaces(self, targets):
		self.identifyPool = {}
		# Start progress manager, abort if there are no devices to evaluate
		new_identify_devices = len(targets)
		self.progress.setTarget(new_identify_devices)
		if new_identify_devices == 0:
			self.progress.forceFinish()
			self.result = (0, 0, False, [])
			return

		num_pre_devices = len(self.devices)
		toBeRenumbered = []

		worker_queue = queue.Queue()
		for target, params in targets.items():
			worker_queue.put((target, params))

		max_threads = self.hlapi.getConfig('max_threads')
		for i in range(min(len(targets.keys()), max_threads)):
			t = threading.Thread(target=self.scanAndIdentify, args=[worker_queue, toBeRenumbered])
			self.progress.addThreadWatch(t)
			t.start()

		# Wait for all threads to finish
		self.progress.closeThreads()

		devices_added = len(self.devices)-num_pre_devices
		self.result = (devices_added, self.updatedDevices, False, toBeRenumbered)
		self.progress.finish()

	def scanAndIdentify(self, q, toBeRenumbered):
		while self.progress.isRunning():
			try:
				interface, params = q.get_nowait()
			except queue.Empty:
				return

			if self.hlapi.debug: print("Evaluating", interface)
			ad = AbstractDevice(self.hlapi, interface, connection_params=params)

			if '#' in interface:
				scanUnits = [int(interface.split('#')[1])]
			else:
				scanUnits = ad.communicator.scan()

			if scanUnits is not None:
				self.progress.addTarget(len(scanUnits))
				if self.hlapi.debug: print("Scan result at", ad.ip, ":", scanUnits)

				for unit in scanUnits:
					if self.progress.isAborted() or self.progress.isError():
						break
					if unit == 'gateway':
						if interface not in [x.ip for x in self.devices if x is not None and x.devType == 'gateway']:
							device = Gateway(self.hlapi, interface, communicator=ad.communicator)
							device.firstInRing = True
							self.devices.append(device)
						self.progress.addProgress(1)
					elif isinstance(unit, int):
						self.addToIdentifyPool(ad, unit, (unit is scanUnits[0]))
					elif isinstance(unit, str):
						# hardware address to be renumbered
						toBeRenumbered.append((interface, unit))
						self.progress.addProgress(1)
			elif self.hlapi.debug: print("No scan result")

			# Interface scan done
			self.progress.addProgress(1)
			q.task_done()

		# ProgressManager error or aborted, empty queue
		q.mutex.acquire()
		q.queue.clear()
		q.all_tasks_done.notify_all()
		q.unfinished_tasks = 0
		q.mutex.release()

	def loadFile(self, ifile, graphPath=None):
		num_pre_devices = len(self.devices)

		loaddata = [[], []]
		headers = None

		try:
			with open(ifile, "r") as f:
				loaddata = json.load(f)
				headers = loaddata[0]
		except Exception as e:
			if self.hlapi.debug: print("Could not load from file: "+str(e))

		graph_md5_match = False
		if headers is not None and headers.get('compat', 0) == self.hlapi.getConfig('file_compat_nr'):
			if graphPath is not None:
				try:
					if self.hlapi.debug: print("MD5 (file - local):", headers.get('graph_sum', None),"-" , HLAPIHelper.fileMD5(graphPath))
					if headers.get('graph_sum', None) == HLAPIHelper.fileMD5(graphPath):
						graph_md5_match = True
				except:
					pass

			devices = loaddata[1]
			d_list = []

			total_devices = 0
			for bundle in devices:
				total_devices += len(bundle)
			self.progress.setTarget(total_devices)

			if self.hlapi.debug: print("Loading devices from file")
			for bundle in devices:
				comm = None
				for device in bundle:
					if self.progress.isAborted() or self.progress.isError():
						return

					try:
						d_type = device[0]
						d_ip = device[1]
						d_unit = device[2]
						d_mode = device[3]
						d_firstinring = device[4]
						d_ring_status = device[5]
						d_chip_id = device[6]
						d_data = device[7]
					except:
						if self.hlapi.debug: print("File load error, skipping device")
						continue

					if d_type == 'cpdu':
						new_device = cPDU(self.hlapi, d_ip, unit=d_unit, communicator=comm, protocol_order=[])
					elif d_type == 'hpdu':
						new_device = hPDU(self.hlapi, d_ip, unit=d_unit, communicator=comm, protocol_order=[])
					elif d_type == 'hpdu_g3':
						new_device = hPDU_G3(self.hlapi, d_ip, unit=d_unit, communicator=comm, protocol_order=[])
					elif d_type == 'dpm27e':
						new_device = DPM27e(self.hlapi, d_ip, unit=d_unit, communicator=comm, protocol_order=[])
					elif d_type == 'dpm27':
						new_device = DPM27(self.hlapi, d_ip, unit=d_unit, communicator=comm, protocol_order=[])
					elif d_type == 'dpm3':
						new_device = DPM3(self.hlapi, d_ip, unit=d_unit, communicator=comm, protocol_order=[])
					elif d_type == 'gateway':
						new_device = Gateway(self.hlapi, d_ip, unit=d_unit, communicator=comm, protocol_order=[])

					new_device.cacheExpire = -1
					new_device.firstInRing = d_firstinring
					new_device.ring_status = d_ring_status
					new_device.data = d_data

					if comm is None:
						comm = new_device.communicator

					d_list.append(new_device)
					self.progress.addProgress(1)

			self.devices = d_list
		else:
			self.progress.abort()
			if self.hlapi.debug: print("Incompatible save file")

		devices_added = len(self.devices)-num_pre_devices
		self.result = (devices_added, self.updatedDevices, graph_md5_match, [])
		self.progress.finish()

	# Dumps the devices object to a savefile
	def saveFile(self, ofile, graphPath=None):
		if graphPath is not None:
			try:
				graph_sum = HLAPIHelper.fileMD5(graphPath)
			except:
				graph_sum = None
		else:
			graph_sum = None

		headers = {
			'compat': self.hlapi.getConfig('file_compat_nr'),
			'graph_sum': graph_sum
		}

		s_result = self.getResult('serialized')
		savedata = [headers, s_result]
		try:
			with open(ofile, "w") as f:
				json.dump(savedata, f)
			return True
		except:
			return False

	# If the given unit address belong to an interface for which there is no identification worker yet,
	# start a new one and add this unit to the worker's queue.
	# Otherwise just add the unit address to an existing worker's queue.
	def addToIdentifyPool(self, device, unit, firstInRing):
		if self.progress.isAborted() or self.progress.isError():
			return

		alt_device = self.getDevice(device.ip, unit)
		if alt_device is not None:
			self.updatedDevices += 1
			if self.hlapi.debug: print("Device", device.ip, unit, "exists, copying cache...")
			device.load(data=alt_device.data)
			self.devices.remove(alt_device)

		if device.ip in self.identifyPool:
			q = self.identifyPool.get(device.ip)
			q.put((unit, firstInRing))
		else:
			t = threading.Thread(target=self.identifyPoolWorker, args=[device])
			self.progress.addThreadWatch(t)
			q = queue.Queue()
			q.put((unit, firstInRing))
			self.identifyPool[device.ip] = q
			t.start()

	# One worker per IP address
	# Takes a unit address from the queue for this interface and identifies the device
	# The result will either be None on fail or a Device object.
	def identifyPoolWorker(self, masterAd):
		unitQueue = self.identifyPool.get(masterAd.ip)
		while True:
			# Fetch unit from queue or empty queue on abort
			try:
				unit, first = unitQueue.get_nowait()
				if self.progress.isAborted() or self.progress.isError():
					unitQueue.mutex.acquire()
					unitQueue.queue.clear()
					unitQueue.all_tasks_done.notify_all()
					unitQueue.unfinished_tasks = 0
					unitQueue.mutex.release()
					break
			except queue.Empty:
				break

			# Read identification and configuration groups
			idGroupData = masterAd.communicator.read('identification', 'group', unit)

			# Determine device type
			newDevice = None
			if idGroupData is not None and idGroupData != 'TIMEOUT':
				device_type = idGroupData.get('idspdt')
				# 0 = PDU, 1 = DPM, 2 = hPDU_G3, 3 = DPM27/e
				device_fw_version = idGroupData.get('idfwvs')

				# <200 = classic, >=200 = current
				if device_type == 0:
					if device_fw_version < 200:
						cfGroupData = masterAd.communicator.read('configuration', 'group', unit)
						if cfGroupData is not None and cfGroupData != 'TIMEOUT':
							if cfGroupData.get('cfnrph') == 0 and cfGroupData.get('cfnrno') == 27:
								newDevice = DPM27(self.hlapi, masterAd.ip, unit, communicator=masterAd.communicator)
							else:
								newDevice = cPDU(self.hlapi, masterAd.ip, unit, communicator=masterAd.communicator)
							masterAd.data['configuration'] = [time.time(), cfGroupData]
						else:
							if self.hlapi.debug: print("Could not read configuration group to determine DPM27/cPDU")
					else:
						newDevice = hPDU(self.hlapi, masterAd.ip, unit, communicator=masterAd.communicator)
				elif device_type == 1:
					if device_fw_version < 200:
						newDevice = DPM27(self.hlapi, masterAd.ip, unit, communicator=masterAd.communicator)
					else:
						newDevice = DPM3(self.hlapi, masterAd.ip, unit, communicator=masterAd.communicator)
				elif device_type == 2:
						newDevice = hPDU_G3(self.hlapi, masterAd.ip, unit, communicator=masterAd.communicator)
				elif device_type == 3:
						newDevice = DPM27e(self.hlapi, masterAd.ip, unit, communicator=masterAd.communicator)

				else:
					if self.hlapi.debug: print("Invalid device type:", device_type, "firmware version:", device_fw_version)

				if newDevice is not None:
					newDevice.load(data=masterAd.data)
					newDevice.data['identification'] = [time.time(), idGroupData]
					newDevice.firstInRing = first
				else:
					self.unknownDevices.append((masterAd.ip, unit))

			else:
				ipapi = masterAd.communicator.getProtocol('IPAPI')
				if ipapi is not None and ipapi.isGateway():
					newDevice = Gateway(self.hlapi, masterAd.ip, communicator=masterAd.communicator)
				else:
					self.unknownDevices.append((masterAd.ip, unit))

			if newDevice is not None:
				if self.getDevice(newDevice.ip, newDevice.unitAddress) is not None:
					if self.hlapi.debug: print("Error! Device exists already, not possible!")
				else:
					self.devices.append(newDevice)

			self.progress.addProgress(1)
			unitQueue.task_done()

		if self.hlapi.debug: print("Identify thread", masterAd.ip, "done")

	def applySettingsAllDevices(self):
		for device in self.getResult('raw'):
			com = device.communicator
			if com is not None:
				ipapi = com.getProtocol('IPAPI')
				if ipapi is not None:
					ipapi.timeout = self.hlapi.getConfig('ipapi_timeout')
					ipapi.yieldSeconds = self.hlapi.getConfig('ipapi_yield')
				webapi = com.getProtocol('WEBAPI')
				if webapi is not None:
					webapi.timeout = self.hlapi.getConfig('webapi_timeout')
			device.cacheExpire = self.hlapi.getConfig('cache_expire')

	def getDevice(self, ip, unit):
		for d in self.getResult('raw'):
			if d.ip == ip and d.unitAddress == unit:
				return d
		return None


	def getResult(self, output=None, filter=None):
		if filter is None:
			filter = self.devices

		if output == 'raw':
			# Return list of devices
			return filter
		elif output == 'serialized':
			# Return 2D list of devices containing serialized connection data
			s_result = []
			bundled = HLAPIHelper.bundleDevicesByCommunicator(filter)
			for bundle in bundled:
				b_result = []
				for device in bundle:
					d_type = HLAPIHelper.deviceToType(device)
					d_ip = device.ip
					d_unit = device.unitAddress
					d_mode = device.read('ethmod', 'single', extract=True)
					d_firstinring = device.firstInRing
					d_ringstatus = device.ring_status
					d_chipid = device.read('idchip', 'single', extract=True)
					d_data = device.data
					b_result.append([d_type, d_ip, d_unit, d_mode, d_firstinring, d_ringstatus, d_chipid, d_data])
				s_result.append(b_result)
			return s_result
		else:
			result = HLAPIHelper.generateInterfaceDict(self.getResult('raw', filter=filter))
			return result
