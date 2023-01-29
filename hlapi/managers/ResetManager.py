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
import time
import threading

# Local imports
from .. Helper import Helper as HLAPIHelper
from .. communication.Communicator import Communicator
from .. communication.IPAPIProtocol import IPAPIProtocol
from .. communication.IPAPIFramer import *
from .. spdm.RegisterHelper import RegisterHelper


class ResetManager(object):
	def __init__(self, hlapi_instance, devices):
		self.hlapi = hlapi_instance

		if isinstance(devices, list):
			self.devices = devices
		else:
			self.devices = [devices]

		self.result = None
		self.progress = HLAPIHelper.createProgressManager(self.hlapi, name='ResetManager', explicitFinish=True)

	# Reset connections to all communicators
	def resetConnections(self):
		bundled = HLAPIHelper.bundleDevicesByCommunicator(self.devices)
		for bundle in bundled:
			communicator = bundle[0].communicator
			if self.hlapi.debug: print('Resetting connection to', communicator.ip)
			communicator.initProtocols()

	def startReboot(self, resetComm=False):
		t = threading.Thread(target=self.reboot, kwargs={'resetComm':resetComm})
		self.progress.addThreadWatch(t)
		t.start()

	# Raw reboot all devices
	# The provided list of devices (self.devices) must be correct in ring order
	# to make sure rebooting devices prevent other from passing on the reboot command
	# unit_list = sorted(raw_databus_scan_list, key=lambda x: list_a.index(x))
	# can be used to order a list of units in databus ring order
	def reboot(self, resetComm=False, broadcast=False):
		self.progress.reset()

		bundled = HLAPIHelper.bundleDevicesByCommunicator(self.devices)
		communicators = [x[0].communicator for x in bundled]
		units = [[x.unitAddress for x in bundle] for bundle in bundled]

		self.progress.setTarget(len(communicators))

		if broadcast:
			for communicator in communicators:
				# Send reboot frame to each communicator 3 times
				ipapi = communicator.getProtocol('IPAPI')
				if ipapi is not None:
					f = Frame()
					f.Fields = BroadcastWriteRegisterFields
					f.setField(COMMAND, f.CMD_BRWRITE[0])
					f.setField(REGISTERSTART, 400)
					f.setField(REGISTERLENGTH, 1)
					f.setField(DATA, ipapi._serialize(1, RegisterHelper.registerLookup('rsboot')))

					if self.hlapi.debug: print('Sending reboot broadcast frame to', ipapi.ip)

					for i in range(3):
						ipapi.broadcast(f)
						time.sleep(0.05)
				self.progress.addProgress(1)
		else:
			# Write rsboot=1 register to each device
			for i in range(len(communicators)):
				if self.hlapi.debug: print("Rebooting units", units[i], "at", communicators[i].ip)
				communicators[i].rebootUnits(units[i])
				self.progress.addProgress(1)
		if resetComm:
			time.sleep(20)
			self.resetConnections()
		self.progress.finish()
