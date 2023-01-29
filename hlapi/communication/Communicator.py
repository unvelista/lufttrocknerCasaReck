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
import copy

# Local imports
from . IPAPIProtocol import IPAPIProtocol
from . IPAPIFramer import *
from . WEBAPIProtocol import WEBAPIProtocol
from .. spdm.RegisterHelper import RegisterHelper
from .. spdm.Registers import *
from .. Helper import Helper as HLAPIHelper

# Handles high-level communication to an interface IP:PORT
# Automatically chooses underlying protocol (WEBAPI, IPAPI, ...) depending on a
# preffered order and protocol availability
#
class Communicator(object):
	def __init__(self, hlapi_instance, ip, connection_params, protocol_order):
		self._protocols = {}
		self.hlapi = hlapi_instance
		self.ip = ip
		self.connection_params = connection_params
		self.protocol_order = protocol_order
		if connection_params is None:
			self._setNoneProtocols()
		else:
			self.initProtocols()

	def initProtocols(self):
		self.consecutiveFails = {'IPAPI':0, 'WEBAPI':0}
		
		# Initialise all protocols
		if self.hlapi.debug: print("Setting up protocols for", self.ip)
		if 'WEBAPI' in self.protocol_order:
			if 'WEBAPI' in self._protocols:
				del self._protocols['WEBAPI']
			result = self._setupProtocol('WEBAPI', WEBAPIProtocol(self.hlapi, self.ip, self.connection_params))
			if self.hlapi.debug: print("WEBAPI:", result)

		if 'IPAPI' in self.protocol_order:
			if 'IPAPI' in self._protocols:
				del self._protocols['IPAPI']
			result = self._setupProtocol('IPAPI', IPAPIProtocol(self.hlapi, self.ip, self.connection_params))
			if self.hlapi.debug: print("IPAPI:", result)

	# Returns an initialised protocol or None
	#
	def getProtocol(self, protocolName):
		if protocolName in self._protocols:
			return self._protocols[protocolName]
		else:
			return None

	# Registers a protocol to this instance and checks if the connection was successful
	#
	def _setupProtocol(self, name, obj):
		self._protocols[name] = obj
		if self._protocols[name].conn is False:
			self._protocols[name] = None
			return False
		return True

	def _setNoneProtocols(self):
		for protocolName in self._protocols:
			self._protocols[protocolName] = None

	def setProtocolOrder(self, order):
		self.protocol_order = order

	def protocolOrderDownShift(self, protocol):
		oldindex = self.protocol_order.index(protocol)
		if oldindex < len(self.protocol_order)-1:
			if self.hlapi.debug: print("Decreasing", protocol, "priority in protocol order for", self.ip)
			newindex = oldindex+1
			self.protocol_order.insert(newindex, self.protocol_order.pop(oldindex))

	# Read a register or group from a specific unit by trying the available protocols in a given order
	#
	# Input:	readValue: register mnemonic or group name
	#			readType: either 'single' or 'group'
	#			unitAddress: unit address
	#			overrides: a dictionary of mnemonic:Register instances that need to be overridden for this read
	#			suppress: if True, no warnings will be if self.hlapi.debug: printed if a value cannot be read
	# Output:	A dictionary of (a) mnemonic:value pair(s) or None
	def read(self, readValue, readType, unitAddress, overrides={}):
		current_order = copy.copy(self.protocol_order)
		for protocol in current_order:
			if self._protocols[protocol] is not None:
				if self.hlapi.debug: print("Read", readType, readValue, "@", self.ip, "unit", unitAddress, "with", protocol)
				value = None
				if readType == 'single':
					# Apply override if given
					if readValue in overrides:
						register = overrides[readValue]
					else:
						register = RegisterHelper.registerLookup(readValue)
						# Check if the given mnemonic is valid
						if register is None:
							if self.hlapi.debug: print('-> Invalid mnemonic')
							return False
					# Verify if the given register is readable by the current protocol
					if protocol.lower() not in register.Read.lower() and register.Read.lower() != 'all':
						# Dummy response for eg. password register
						if register.Read == '*':
							value = {register.Mnemonic:['']*register.Repeats}
						elif self.hlapi.debug:
							print('-> Not readable by', protocol, 'not in', register.Read)
							value = None
					else:
						# Make the underlying protocol read the register
						value = self._protocols[protocol].readRegister(register, unitAddress)

				elif readType == 'group':
					# Get all registers for the given SPDM group
					registerList = [x for x in Registers if x.Group == readValue]
					# Apply overrides if given
					registerList = [overrides.get(x.Mnemonic) if x.Mnemonic in overrides else x for x in registerList]
					# Filter to readable registers only
					registerList = [x for x in registerList if protocol.lower() in x.Read.lower() or x.Read.lower() == 'all']
					# Sort registers by registerstart ascending
					registerList.sort(key=lambda x: x.RegisterStart)

					if len(registerList) > 0:
						# Make the underlying protocol read the group
						value = self._protocols[protocol].readGroup(registerList, readValue, unitAddress)
					else:
						if self.hlapi.debug: print('-> Group '+str(readValue)+' not readable by', protocol)
						value = None

				# If everything went well, return. If not, try again using the next protocol
				if value is not None:
					try:
						if value != 'TIMEOUT':
							if self.hlapi.debug: print("-> Success, result =", value)
							self.consecutiveFails[protocol] = 0
							return value
						else:
							if self.hlapi.debug: print('TIMEOUT, trying next protocol')
					except:
						if self.hlapi.debug: print("-> Success, result not printable")

				else:
					if self.hlapi.debug: print("-> Fail, trying next protocol")
					self.consecutiveFails[protocol] += 1
					if self.consecutiveFails[protocol] > self.hlapi.getConfig('downshift_tries'):
						self.protocolOrderDownShift(protocol)

		# If all protocols have been tried without success, if self.hlapi.debug: print a warning
		return self.noCommunicators('read', {'value':readValue, 'type':readType, 'unit':unitAddress})

	# Write data to one or more registers on a specific unit by trying the available protocols in a given order
	#
	# Input:	writeValue: register mnemonic or group name
	#			writeType: either 'single' or 'group'
	#			unitAddress: unit address
	#			data: either a single value or a list of values that correspond to the registers in the specified group
	#			overrides: a dictionary of mnemonic:Register instances that need to be overridden for this write
	#			suppress: if True, no warnings will be if self.hlapi.debug: printed if a value cannot be written
	# Output:	True or False for a single write, a list of T/F values for a group write
	def write(self, writeValue, writeType, unitAddress, data, overrides={}):
		current_order = copy.copy(self.protocol_order)
		for protocol in current_order:
			if self._protocols[protocol] is not None:
				if self.hlapi.debug: print("Write", writeType, writeValue, "@", self.ip, "unit", unitAddress, "data:", data, "with", protocol)
				value = None
				if writeType == 'single':
					# Apply override if given
					if writeValue in overrides:
						register = overrides[writeValue]
					else:
						# Check if the given mnemonic is valid
						register = RegisterHelper.registerLookup(writeValue)
						if register is None:
							if self.hlapi.debug: print('-> Invalid mnemonic')
							return False

					# Verify if the given register is writable by the current protocol
					if (protocol.lower() not in register.Write.lower() and register.Write.lower() != 'all') or register.WriteAccess == '-':
						if self.hlapi.debug: print('-> Not writable by', protocol, 'not in', register.Write)
						value = None
					else:
						# Validate the given input data according the the register's SPDM specifications
						canwrite = RegisterHelper.checkWriteInput(register, data)
						if canwrite is not True:
							if self.hlapi.debug: print('->', canwrite)
							return False

						# Make the underlying protocol write to the register
						value = self._protocols[protocol].writeRegister(register, unitAddress, data)
						# Check if write successful
						if value is False:
							if self.hlapi.debug: print("-> Write fail")
							value = None

				elif writeType == 'group':
					# Get all registers for the given SPDM group
					registerList = [x for x in Registers if x.Group == writeValue]
					# Apply overrides if given
					registerList = [overrides.get(x.Mnemonic) if x.Mnemonic in overrides else x for x in registerList]
					# Sort registers by registerstart ascending
					registerList.sort(key=lambda x: x.RegisterStart)
					# Generate a boolean list of 'writability' for each register
					writeStatus = {}
					for register in registerList:
						if (protocol.lower() not in register.Write.lower() and register.Write.lower() != 'all') or register.WriteAccess == '-':
							writeStatus[register.Mnemonic] = False
						else:
							# Validate the given input data according the the register's SPDM specifications
							canwrite = RegisterHelper.checkWriteInput(register, data[register.Mnemonic])
							if canwrite is not True:
								if self.hlapi.debug: print('->', canwrite)
								canwrite = False
							writeStatus[register.Mnemonic] = canwrite

					# Make the underlying protocol write data to all registers that are writable and have valid input data
					value = self._protocols[protocol].writeGroup(registerList, writeValue, unitAddress, data, writeStatus)

				# If everything went well, return. If not, try again using the next protocol
				# the return value is either None or a boolean list indicating write success/fail
				# for each register
				if value is not None:
					if value != 'TIMEOUT':
						if self.hlapi.debug: print("-> Success, result =", value)
						self.consecutiveFails[protocol] = 0
						return value
					else:
						if self.hlapi.debug: print('TIMEOUT, trying next protocol')
				else:
					self.consecutiveFails[protocol] += 1
					if self.consecutiveFails[protocol] > self.hlapi.getConfig('downshift_tries'):
						self.protocolOrderDownShift(protocol)

		# If all protocols have been tried without success, if self.hlapi.debug: print a warning
		return self.noCommunicators('write', {'value':writeValue, 'type':writeType, 'unit':unitAddress})

	# Performs a databus scan on this interface
	# input:	timeout: maximum number of seconds to wait between responses from devices on the databus until returning
	# output:	A list of found unit addresses on the databus
	def scan(self):
		current_order = copy.copy(self.protocol_order)
		scan_timeout = self.hlapi.getConfig('scan_timeout')
		for protocol in current_order:
			if protocol == 'IPAPI' and self._protocols[protocol] is not None:
				device_list = []
				# Check if the current interface is a gateway
				if self.hlapi.debug: print("Scanning", self.ip, "using IPAPI (t="+str(scan_timeout)+")")
				if self.hlapi.debug: print("Checking if", self.ip, "is a gateway...")
				if self._protocols[protocol].isGateway():
					if self.hlapi.debug: print(str(self.ip)+" is a gateway")
					device_list.append( 'gateway' )

				if self.hlapi.debug: print("Sending scan broadcast frame and collecting responses...")
				# Componse SPBUS scan frame
				f = Frame()
				f.setField(COMMAND, f.CMD_BRSCAN[0])
				# Broadcast the frame onto the SPBUS
				responses = self._protocols[protocol].broadcast(f, collect=True, collectTimeout=scan_timeout)
				if self.hlapi.debug: print("Raw scan result for", self.ip, "(IPAPI):", responses)
				if responses is not None and responses != 'TIMEOUT':
					if self.hlapi.debug: print("Got", str(len(responses)), "response frames")
					if len(responses) == 0:
						if self.hlapi.debug: print("RC4 key could be wrong, trying next protocol")
						continue
					for frame in responses:
						unitAddr = frame.findField(UNITADDRESS).value
						if unitAddr == 0:
							if self.hlapi.debug: print(str(frame.findField(HARDWAREID)))
							device_list.append(str(frame.findField(HARDWAREID).value))
						elif unitAddr in device_list:
							if self.hlapi.debug: print(str(frame.findField(HARDWAREID)))
							index = device_list.index(unitAddr) # find existing device index
							device_list[index] = str(responses[index].findField(HARDWAREID).value) # replace by that device's hwid
							device_list.append(str(frame.findField(HARDWAREID).value)) # add current device's hwid
						else:
							device_list.append(unitAddr)
					self.consecutiveFails[protocol] = 0
					# device_list is now a list of unit addresses and hardware addresses to be renumbered
					return device_list

			elif protocol == 'WEBAPI' and self._protocols[protocol] is not None:
				device_list = []
				if self.hlapi.debug: print("Scanning", self.ip, "using WEBAPI (t="+str(scan_timeout)+")")
				# Send a scan command using the WEBAPI protocol
				scan_result = self._protocols[protocol].sendRaw('/scan', 'POST', timeoutOverride=scan_timeout)
				if self.hlapi.debug: print("Raw scan result for", self.ip, "(WEBAPI):", scan_result)
				# Parse the result
				if scan_result is not None and scan_result != 'TIMEOUT':
					scan_result = scan_result[0]
					nested_devices = int(scan_result['scan_total'])
					scan_total = int(nested_devices)
					if self.hlapi.debug: print("Got", str(scan_total), "devices")
					dupes = []
					for i in range(1, scan_total+1):
						unit_addr = int(scan_result['scan_addr_'+str(i)])
						if unit_addr == 0:
							device_list.append(str(scan_result['scan_hwid_'+str(i)]))
						elif unit_addr in device_list:
							index = device_list.index(unit_addr) # find existing device index
							device_list[index] = str(scan_result['scan_hwid_'+str(index+1)]) # replace by that device's hwid
							device_list.append(str(scan_result['scan_hwid_'+str(i)])) # add current device's hwid
						else:
							device_list.append( unit_addr )
					self.consecutiveFails[protocol] = 0
					# device_list is now a list of unit addresses and hardware addresses to be renumbered
					return device_list

			self.consecutiveFails[protocol] += 1
			if self.consecutiveFails[protocol] > self.hlapi.getConfig('downshift_tries'):
				self.protocolOrderDownShift(protocol)

		return self.noCommunicators('scan', {})

	def setUnitAddress(self, hwid, addr):
		current_order = copy.copy(self.protocol_order)
		if isinstance(hwid, list):
			hwid = "-".join([str(x) for x in hwid])
		for protocol in current_order:
			if protocol == 'IPAPI' and self._protocols[protocol] is not None:
				if self.hlapi.debug: print("setUnitAddress using IPAPI", hwid, addr)
				response = self._protocols[protocol].setUnitAddress(hwid, addr)
				if response is not None and response != 'TIMEOUT':
					self.consecutiveFails[protocol] = 0
					return True
			elif protocol == 'WEBAPI' and self._protocols[protocol] is not None:
				if self.hlapi.debug: print("setUnitAddress using WEBAPI", hwid, addr)
				response = self._protocols[protocol].sendRaw('/address/'+str(hwid), 'POST', data={'idaddr':addr})
				if response is not None and response != 'TIMEOUT':
					return True

			self.consecutiveFails[protocol] += 1
			if self.consecutiveFails[protocol] > self.hlapi.getConfig('downshift_tries'):
				self.protocolOrderDownShift(protocol)
		return self.noCommunicators('setUnitAddress', {'hwid':hwid, 'addr':addr})

	def rebootUnits(self, units):
		current_order = copy.copy(self.protocol_order)
		bootRegister = RegisterHelper.registerLookup('rsboot')
		for protocol in current_order:
			if protocol == 'IPAPI' and self._protocols[protocol] is not None:
				for unit in units:
					self._protocols[protocol].writeRegister(bootRegister, unit, 1)
				return True
			elif protocol == 'WEBAPI' and self._protocols[protocol] is not None:
				for unit in units:
					self._protocols[protocol].writeRegister(bootRegister, unit, 1)
				return True
		return self.noCommunicators('rebootUnits', {'units':units})

	def hasProtocol(self):
		for key, value in self._protocols.items():
			if value is not None and value.conn is True:
				return True
		return False

	def whichProtocols(self):
		result = []
		for key, value in self._protocols.items():
			if value is not None and value.conn is True:
				result.append(key)
		return result

	def noCommunicators(self, action, data):
		for protocol in self.protocol_order:
			if self._protocols[protocol] is not None and self._protocols[protocol].conn == False:
				if self.hlapi.debug: print('-> Disabled protocol', protocol, 'for', self.ip)
				self._protocols[protocol] = None

		if self.hlapi.debug: print('-> No protocols available for '+str(action)+' @', self.ip, 'data =', data)
		return None
