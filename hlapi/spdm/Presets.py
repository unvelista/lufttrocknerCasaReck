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
from .. Helper import Helper as HLAPIHelper
from . RegisterHelper import RegisterHelper
from . Registers import *

class Presets(object):
	def __init__(self, hlapi_instance):
		self.hlapi = hlapi_instance
		self.presets = self.hlapi.getConfig('presets')

	def getKeys(self):
		return list(self.presets.keys())

	def getPreset(self, name):
		if name in self.presets:
			return self.presets[name]
		return None

	def getAllPresets(self):
		return self.presets.items()

	def writePresets(self):
		conf = self.hlapi.getConfig()
		conf['presets'] = self.presets
		self.hlapi.writeConfig(conf)

	def updatePreset(self, preset, mnemonics):
		self.presets[preset] = mnemonics
		self.writePresets()

	def deletePreset(self, preset):
		if preset in self.presets:
			del self.presets[preset]
			self.writePresets()
