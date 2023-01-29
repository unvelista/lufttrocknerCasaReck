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
from copy import deepcopy
import time
from json import JSONEncoder

# Local imports
from .. communication.Communicator import Communicator
from .. spdm.RegisterHelper import RegisterHelper
from .. Helper import Helper as HLAPIHelper

# Trick to allow JSON encoding of AbstractDevice by overriding JSONEncoder.default
def _default(self, obj):
    return getattr(obj.__class__, "to_json", _default.default)(obj)

_default.default = JSONEncoder().default
JSONEncoder.default = _default

# AbstractDevice class represents a device
# This class can be instanciated but inheritance through a specific device (hPDU, Gateway, ...)
# allows for better use since we don't know whether an AbstractDevice instance represents a specific device
# or an interface.
class AbstractDevice(object):
	def __init__(self, hlapi_instance, ip, unit=None, connection_params=None, communicator=None, protocol_order=None):
		self.hlapi = hlapi_instance
		self.ip = ip
		if unit is not None:
			self.unitAddress = unit
			self.uid = str(self.ip).replace(':', '')+'#'+str(self.unitAddress)
		else:
			self.unitAddress = None
			self.uid = None

		if protocol_order is None:
			self.order = hlapi_instance.DEFAULT_PROTOCOL_ORDER
		else:
			self.order = protocol_order

		# Create a communicator for this device or interface or inherit it.
		if communicator is None:
			self.communicator = Communicator(self.hlapi, self.ip, connection_params, self.order)
		else:
			self.communicator = communicator

		self.deviceSpecificRegisterOverrides = {}
		self.data = {}
		self.cacheExpire = hlapi_instance.getConfig('cache_expire')

		self.firstInRing = None
		self.ring_status = None

		self.devType = HLAPIHelper.deviceToType(self)

	def to_json(self):
		return {
			'type': self.devType,
			'ip': self.ip,
			'unit': self.unitAddress
		}

	def load(self, firstInRing=None, ring_status=None, data=None):
		if firstInRing is not None:
			self.firstInRing = firstInRing
		if ring_status is not None:
			self.ring_status = ring_status
		if data is not None:
			self.data = deepcopy(data)

	def getUid(self):
		if self.unitAddress is not None:
			return str(self.ip) + '#' + str(self.unitAddress)
		else:
			return None

	# Read a register or group from this device.
	# This wrapper function implements caching of all data per-device
	#
	# Input:	readValue: register mnemonic or group name
	#			readType: 'single' or 'group'
	def read(self, readValue, readType, cache=True, extract=False):
		cacheTime = self.cacheExpire
		if readType == 'group':
			if readValue in self.data:
				groupData = self.data[readValue]
				if cache is True and (readValue == 'identification' or (groupData is not None and (time.time()-groupData[0] < cacheTime or cacheTime == -1))):
					if groupData[1] == 'TIMEOUT':
						return None
					return groupData[1]

			if self.communicator.hasProtocol():
				data = self.communicator.read(readValue, readType, self.unitAddress, overrides=self.deviceSpecificRegisterOverrides)
				if data is not None:
					self.data[readValue] = [time.time(), data]
					if data == 'TIMEOUT':
						return None
					return data

		elif readType == 'single':
			reg = RegisterHelper.registerLookup(readValue)
			if reg is None:
				if self.hlapi.debug: print("Invalid register:", readValue)
				return None

			if not self.canReadRegister(reg):
				if self.hlapi.debug: print("Device", self.devType, "at", self.getUid(), "is not allowed to access register", readValue)
				return None

			if reg.Group in self.data:
				groupData = self.data.get(reg.Group, None)
				# Identification group is permanently cached since it can only change by user actions
				if cache is True and (reg.Group == 'identification' or (groupData is not None and (time.time()-groupData[0] < cacheTime or cacheTime == -1))):
					if readValue in groupData[1]:
						if extract:
							return groupData[1][readValue]
						else:
							return {readValue: groupData[1][readValue]}

			if self.communicator.hasProtocol():
				data = self.communicator.read(reg.Group, 'group', self.unitAddress, overrides=self.deviceSpecificRegisterOverrides)
				if data is not None:
					self.data[reg.Group] = [time.time(), data]
					if data == 'TIMEOUT':
						return None
					targetValue = data.get(readValue, None)
					if targetValue is not None:
						if extract:
							return targetValue
						else:
							return {readValue: targetValue}

				data = self.communicator.read(readValue, 'single', self.unitAddress, overrides=self.deviceSpecificRegisterOverrides)
				if data is not None:
					if data == 'TIMEOUT':
						return None
					if self.hlapi.debug: print("Group -> single read fallback success")

					if extract:
						return HLAPIHelper.extract(data)
					else:
						return data

		if self.hlapi.debug: print("Read FAIL")
		return None

	def clearFromCache(self, mnemonic):
		reg = RegisterHelper.registerLookup(mnemonic)
		if reg is not None and reg.Group in self.data:
			entry = self.data.get(reg.Group)
			oldTimeStamp = entry[0]
			groupData = entry[1]
			if mnemonic in groupData:
				del groupData[mnemonic]
			self.data[reg.Group] = [oldTimeStamp, groupData]

	def clearAllCache(self):
		self.data = {}

	# Write a register or group of values to this device, clear cached data afterwards.
	def write(self, writeValue, writeType, data):
		if self.communicator.hasProtocol() and data is not None:
			if writeType == 'single' and writeValue == 'idaddr':
				result = self.setUnitAddress(data)
			elif writeType == 'single' and writeValue == 'login':
				result = self.setCredentials(data)
			elif writeType == 'single' and writeValue == 'irc4k':
				result = self.setRC4Key(data)
			else:
				# When doing a group write, 'special' registers are not taken into account.
				# luckily, group writes are not supported by any protocol.
				result = self.communicator.write(writeValue, writeType, self.unitAddress, data, overrides=self.deviceSpecificRegisterOverrides)
			if result == 'TIMEOUT':
				return None
			elif result == True:
				if writeType == 'single':
					self.clearFromCache(writeValue)
				elif writeType == 'group':
					for mnemonic in result.keys():
						self.clearFromCache(mnemonic)
			return result
		else:
			return None

	def isOnline(self):
		return (self.communicator.hasProtocol())

	# Change this devices' unit address to 'value'
	def setUnitAddress(self, value):
		if RegisterHelper.isValidUnitAddress(value):
			hid = self.read('idchip', 'single')
			if hid is not None:
				hid = HLAPIHelper.extract(hid)
				if self.hlapi.debug: print("Changing unit address from", self.unitAddress, "to", value, "(device HID = "+str(hid)+")")
				result = self.communicator.setUnitAddress(hid, value)
				if result == True:
					self.unitAddress = value
					return True
		return False

	def setCredentials(self, data):
		for pair in data:
			if not RegisterHelper.validateUserPass(pair[0], pair[1]):
				if self.hlapi.debug: print("Invalid credentials entered for user", str(pair[0]))
				return False

		# We now have a list of valid (username, password) tuples
		webapi = self.communicator.getProtocol('WEBAPI')
		if webapi is not None:
			# Update WEBAPI login and make sure the current connection is retained
			currentUserID = webapi.sync.userid
			newLoginCurrent = data[currentUserID]

			status = webapi.updateCredentials(data)
			if self.hlapi.debug: print("Credentials update status:", status)

			self.clearFromCache('usname')
			if newLoginCurrent is not None and status is not None and status[currentUserID] is True:
				# Update internal credentials on success
				self.communicator.connection_params['webapi_user'] = newLoginCurrent[0]
				if newLoginCurrent[1] is not None and len(newLoginCurrent[1]) > 0:
					self.communicator.connection_params['webapi_pass'] = newLoginCurrent[1]

			# Only check for success stating from current user level
			return not False in status[currentUserID:]
		else:
			if self.hlapi.debug: print("Could not update credentials: WEBAPI not connected")
			return False

	def setRC4Key(self, key):
		key = RegisterHelper.validateIPAPIKey(key)
		if key is None:
			return False

		if self.communicator.write('iarc4k', 'single', self.unitAddress, key, overrides=self.deviceSpecificRegisterOverrides) is True:
			# Update the IPAPI key and make sure the current connection is retained
			self.communicator.connection_params['ipapi_key'] = newIPAPIKey
			ipapi = self.communicator.getProtocol('IPAPI')
			if ipapi is not None:
				ipapi.key = newIPAPIKey

	def isHybridMaster(self):
		if self.read('ethmod', 'single', extract=True) == 0 or self.read('ethmod', 'single', extract=True) == 5 or self.read('ethmod', 'single', extract=True) == 13 or self.read('ethmod', 'single', extract=True) == 21:
			# classic, hybrid, colo infra or colo enduser
			return True
		return False

	def assumeRingMaster(self):
		return (self.devType in ['hpdu', 'hpdu_g3', 'dpm3', 'dpm27e', 'gateway'] and self.firstInRing is True)

	def isRingMaster(self):
		return self.assumeRingMaster() or self.read('ethmod', 'single', extract=True) == 7 or self.read('ethmod', 'single', extract=True) == 39

	def canReadRegister(self, register):
		if register.Mnemonic in self.deviceSpecificRegisterOverrides:
			register = self.deviceSpecificRegisterOverrides[register.Mnemonic]
		return self.hasDeviceSpecificAccess(register)

	def canWriteRegister(self, register):
		if register.Mnemonic in self.deviceSpecificRegisterOverrides:
			register = self.deviceSpecificRegisterOverrides[register.Mnemonic]

		protocols = self.communicator.whichProtocols() # all connected protocols
		register_write = register.Write

		if not self.hasDeviceSpecificAccess(register):
			return 'not writable'

		# We can access this register through IPAPI
		if 'IPAPI' in protocols and 'IPAPI' in register_write or register_write == 'ALL':
			return True

		# No IPAPI access, check WEBAPI access
		if 'WEBAPI' in protocols and 'WEBAPI' in register_write or register_write == 'ALL':
			# Check WEBAPI access level
			username = self.communicator.getProtocol('WEBAPI').username
			if not RegisterHelper.writableByUser(register, username):
				return 'no access'
			else:
				return True

		# No IPAPI nor WEBAPI access
		return 'not writable'

	def hasDeviceSpecificAccess(self, register):
		return NotImplementedError
