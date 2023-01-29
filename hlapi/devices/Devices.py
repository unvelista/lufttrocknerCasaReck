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

# Local imports
from . AbstractDevice import AbstractDevice
from .. spdm.RegisterHelper import RegisterHelper
from .. spdm.Registers import *

# Specific device classes that inherit AbstractDevice
# self.deviceSpecificRegisterOverrides is a mnemonic:Register dictionary of SPDM register instances that need to be used
#	instead of the default ones when reading or writing
# self.defaultOrder is a tuple of protocol names in which the protocols available to this device will
#	be tried by the communicator
# self.isRingMaster() return True if this device is a databus ring master.

class cPDU(AbstractDevice):
	deviceSpecificRegisterOverrides = {

	}

	def __init__(self, *args, **kwargs):
		super(cPDU, self).__init__(*args, **kwargs)
		self.defaultOrder = ('IPAPI',)
		self.deviceSpecificRegisterOverrides = cPDU.deviceSpecificRegisterOverrides

	def hasDeviceSpecificAccess(self, register):
		if register.Added > 0:
			if register.Added > 200:
				return False
			elif self.read('idfwvs', 'single', extract=True) is not None and register.Added > self.read('idfwvs', 'single', extract=True):
				return False
		return not register.Read == "WEBAPI"

class hPDU(AbstractDevice):
	deviceSpecificRegisterOverrides = {

	}

	def __init__(self, *args, **kwargs):
		super(hPDU, self).__init__(*args, **kwargs)
		self.defaultOrder = ('WEBAPI','IPAPI')
		self.deviceSpecificRegisterOverrides = hPDU.deviceSpecificRegisterOverrides

	def hasDeviceSpecificAccess(self, register):
		if register.Added > 0:
			if self.read('idfwvs', 'single', extract=True) is not None and register.Added > self.read('idfwvs', 'single', extract=True):
				return False
		return True

class hPDU_G3(AbstractDevice):
	deviceSpecificRegisterOverrides = {

	}

	def __init__(self, *args, **kwargs):
		super(hPDU_G3, self).__init__(*args, **kwargs)
		self.defaultOrder = ('WEBAPI', 'IPAPI')
		self.deviceSpecificRegisterOverrides = hPDU.deviceSpecificRegisterOverrides

	def hasDeviceSpecificAccess(self, register):
		if register.Added > 0:
			if self.read('idfwvs', 'single', extract=True) is not None and register.Added > self.read('idfwvs', 'single', extract=True):
				return False
		return True

class Gateway(AbstractDevice):
	deviceSpecificRegisterOverrides = {

	}

	def __init__(self, *args, **kwargs):
		super(Gateway, self).__init__(*args, **kwargs)
		self.defaultOrder = ('IPAPI',)
		self.deviceSpecificRegisterOverrides = Gateway.deviceSpecificRegisterOverrides
		self.unitAddress = 0
		self.uid = str(self.ip)+'#'+str(self.unitAddress)

	def hasDeviceSpecificAccess(self, register):
		if register.Mnemonic in ['horist', 'hobrin', 'idfwvs']:
			if register.Mnemonic != 'idfwvs' and self.read('idfwvs', 'single', extract=True) is not None and self.read('idfwvs', 'single', extract=True) == 0:
				return False
			return True
		return False

	def read(self, readValue, readType, cache=True, extract=False):
		if readType == 'single':
			reg = RegisterHelper.registerLookup(readValue)
			if reg is None or not self.canReadRegister(reg):
				return None

			if 'gateway' in self.data and self.data['gateway'] is not None:
				if readValue in self.data['gateway'] and self.data['gateway'].get(readValue) is not None:
					value = self.data['gateway'].get(readValue)
					if extract:
						return value
					else:
						return {readValue: value}

			data = self.communicator.read(readValue, 'single', self.unitAddress, overrides=self.deviceSpecificRegisterOverrides)
			if data is not None:
				if data == 'TIMEOUT':
					return None
				if 'gateway' not in self.data:
					self.data['gateway'] = {}
				if readValue in data:
					self.data['gateway'][readValue] = data[readValue]
				if extract:
					return data[readValue]
				else:
					return data
		return None

	def write(self, writeValue, writeType, data):
		return False

class DPM27(AbstractDevice):
	deviceSpecificRegisterOverrides = {
		'stomct': Register("stomct", 1122, 1, 27, True, INT, "settings", 0, "ALL", "DATABUS, IPAPI, SNMP, MODBUS, DATABUS_INFRA", "power", False, "outputCTratio", "The multiplier to use in case /5 current transformers are used. Defaults to 1."),
		'stimct': Register("stimct", 1149, 1, 3, False, INT, "settings", 0, "ALL", "DATABUS, IPAPI, SNMP, MODBUS, DATABUS_INFRA", "power", False, "inputCTratio", "The multiplier to use in case /5 current transformers are used. Defaults to 1.")
	}

	def __init__(self, *args, **kwargs):
		super(DPM27, self).__init__(*args, **kwargs)
		self.defaultOrder = ('IPAPI',)
		self.deviceSpecificRegisterOverrides = DPM27.deviceSpecificRegisterOverrides

	def hasDeviceSpecificAccess(self, register):
		if register.Added > 0:
			if register.Added > 200:
				return False
			elif self.read('idfwvs', 'single', extract=True) is not None and register.Added > self.read('idfwvs', 'single', extract=True):
				return False
		return not register.Read == "WEBAPI"

class DPM27e(AbstractDevice):
	deviceSpecificRegisterOverrides = {

	}

	def __init__(self, *args, **kwargs):
		super(DPM27e, self).__init__(*args, **kwargs)
		self.defaultOrder = ('WEBAPI','IPAPI')
		self.deviceSpecificRegisterOverrides = hPDU.deviceSpecificRegisterOverrides

	def hasDeviceSpecificAccess(self, register):
		if register.Added > 0:
			if self.read('idfwvs', 'single', extract=True) is not None and register.Added > self.read('idfwvs', 'single', extract=True):
				return False
		return True

class DPM3(AbstractDevice):
	deviceSpecificRegisterOverrides = {
		'stomct': Register("stomct", 1122, 1, 27, True, INT, "settings", 0, "ALL", "DATABUS, IPAPI, SNMP, MODBUS, DATABUS_INFRA", "power", False, "outputCTratio", "The multiplier to use in case /5 current transformers are used. Defaults to 1."),
		'stimct': Register("stimct", 1149, 1, 3, False, INT, "settings", 0, "ALL", "DATABUS, IPAPI, SNMP, MODBUS, DATABUS_INFRA", "power", False, "inputCTratio", "The multiplier to use in case /5 current transformers are used. Defaults to 1.")
	}

	def __init__(self, *args, **kwargs):
		super(DPM3, self).__init__(*args, **kwargs)
		self.defaultOrder = ('WEBAPI','IPAPI')
		self.deviceSpecificRegisterOverrides = DPM3.deviceSpecificRegisterOverrides

	def hasDeviceSpecificAccess(self, register):
		if register.Added > 0:
			if self.read('idfwvs', 'single', extract=True) is not None and register.Added > self.read('idfwvs', 'single', extract=True):
				return False
		return True
