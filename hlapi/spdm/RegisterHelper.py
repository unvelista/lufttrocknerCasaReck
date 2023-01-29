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

from . Registers import *

class RegisterHelper(object):

	@staticmethod
	def intSizeToMax(length):
		if length == 1:
			return 255
		elif length == 2:
			return 65535
		elif length == 3:
			return 16777215
		elif length == 4:
			return 4294967295
		else:
			return 0

	@staticmethod
	def registerLookup(mnemonic):
		for reg in Registers:
			if reg.Mnemonic == mnemonic:
				return reg
		return None

	@staticmethod
	def mnemonicsToRegisters(mnemonics):
		result = []
		for reg in Registers:
			if reg.Mnemonic in mnemonics:
				result.append(reg)
		return result

	@staticmethod
	def isValidUnitAddress(addr):
		try:
			addr = int(addr)
		except:
			return False

		if addr >= 0 and addr < 65536:
			return True
		else:
			return False

	@staticmethod
	def validateUserPass(username, password):
		if len(username) > 16 or len(password) > 16:
			return False
		else:
			return True

	@staticmethod
	def validateIPAPIKey(key):
		if len(key) != 16:
			return None
		try:
			converted = int(key)
		except Exception:
			return None
		return key

	@staticmethod
	def writableByUser(reg, username):
		access = reg.WriteAccess
		if access == '-':
			return False
		elif username == 'super':
			return True
		elif username == 'admin' and access in ['admin', 'power', 'user']:
			return True
		elif username == 'power' and access in ['power', 'user']:
			return True
		elif username == 'user' and access in ['user']:
			return True
		elif username is None:
			return True
		return False

	# Validates input data (to be written to a device register)
	# Returns True if the input data has the right length and data type for the given register
	# If the given register has more than 1 repeat, the input must be a list matching the number of repeats.
	# The length and datatype checks will be performed for each repeat value.
	@staticmethod
	def checkWriteInput(reg, data, device=None):
		if device is not None:
			# Apply device specific register overrides
			if reg.Mnemonic in device.deviceSpecificRegisterOverrides:
				reg = device.deviceSpecificRegisterOverrides[reg.Mnemonic]

		repeats = reg.Repeats
		# Register has multiple channels
		if repeats > 1:
			if isinstance(data, list):
				# If input is list, make sure the list length equals the number of channels
				if reg.Extension:
					# Double number of channels if register is extended
					repeats = repeats * 2
				if len(data) != repeats:
					return 'invalid repeat length'
			else:
				return 'invalid repeat length'

		# Here we know that the length of the input == number of channels
		for i in range(repeats):
			if repeats == 1:
				curData = data
			else:
				curData = data[i]

			# Check type
			if isinstance(curData, int):
				if reg.Type != INT:
					return 'wrong data type'
				if curData > RegisterHelper.intSizeToMax(reg.RegisterLength) or curData < 0:
					return 'invalid data length'
			if isinstance(curData, str):
				if (reg.Type != ASCII and reg.Type != IPV4 and reg.Type != IPV6):
					return 'wrong data type'
				if (reg.Type == ASCII and len(curData) > reg.RegisterLength):
					# ignore ipv4 and ipv6 input length check
					return 'invalid register length'
			if isinstance(curData, float):
				if reg.Type != FD:
					return 'wrong data type'
				if curData > 3276.8 or curData < 0:
					return 'invalid register length'

		return True

	@staticmethod
	def formatData(reg, data):
		repeats = reg.Repeats

		# Register has multiple channels
		if repeats > 1:
			if isinstance(data, list):
				# If input is list, make sure the list length equals the number of channels
				if reg.Extension:
					# Double number of channels if register is extended
					repeats = repeats * 2
				if len(data) != repeats:
					return None
			else:
				return None

		# Here we know that the length of the input == number of channels
		for i in range(repeats):
			try:
				if repeats == 1:
					curData = data
				else:
					curData = data[i]

				# Transform type
				if reg.Type == INT:
					transformed = int(curData)
				if (reg.Type == ASCII or reg.Type == IPV4 or reg.Type == IPV6):
					transformed = str(curData)
				if reg.Type == FD:
					transformed = float(curData)

				if repeats == 1:
					data = transformed
				else:
					data[i] = transformed
			except:
				return None

		return data
