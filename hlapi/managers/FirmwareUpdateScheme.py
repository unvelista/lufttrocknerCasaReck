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
import os
import re

# Local imports
from .. devices.AbstractDevice import AbstractDevice
from .. devices.Devices import *
from .. Helper import Helper as HLAPIHelper

class FirmwareUpdateScheme():
	def __init__(self, device_manager):
		self.deviceManager = device_manager

	def prepareFWUScheme(self, scheme):
		all_hybrids_fast = []

		# Iterate interfaces
		for ip, value in scheme.items():
			current_interface_args = value['args']
			to_remove = []
			# Iterate devices
			for deviceDict in value['devices']:
				current_device = deviceDict['device']

				# Gateways will be removed later
				if isinstance(current_device, Gateway):
					to_remove.append(deviceDict)
					continue

				current_device_args = deviceDict['args']
				broadcast = current_device_args.get('broadcast')

				generation = HLAPIHelper.firmwareToGeneration(current_device.read('idfwvs', 'single', extract=True))
				if generation is None:
					# Invalid firmware version
					to_remove.append(deviceDict)
					continue

				# Set upgrade broadcast if needed
				if broadcast is None or broadcast == False:
					if generation == 'hybrid':
						if current_device.isHybridMaster():
							current_device_args['broadcast'] = False
							current_device_args['fast'] = True
							all_hybrids_fast.append(deviceDict)
						elif broadcast is None:
							current_device_args['broadcast'] = True
					else:
						current_device_args['broadcast'] = True

				# Check firmware compatibility
				if not self.isCompatible(current_device, current_device_args['fw']):
					current_device_args['incompatible'] = True

			# Remove gateways
			for deviceDict in to_remove:
				value['devices'].remove(deviceDict)

			# Select all devices in interface that require broadcast (except incompatible devices)
			all_broadcasts = [x for x in value['devices'] if x['args']['broadcast'] == True and x['args'].get('incompatible', False) is False]
			all_broadcast_devices = [x['device'] for x in all_broadcasts]
			broadcast_firmwares = [x['args']['fw'] for x in all_broadcasts]
			# Convert devices to list of target firmware generations (classic, hybrid)
			broadcast_firmware_generations = [HLAPIHelper.firmwareToGeneration(x[0]) for x in broadcast_firmwares if x is not None]

			all_devices = self.deviceManager.getResult()
			# Iterate all devices in interface
			for d in all_devices[ip]['devices']:
				# Skip gateways
				if isinstance(d['device'], Gateway):
					continue
				# Check if device is in selection (collateral upgrades)
				current_gen = HLAPIHelper.firmwareToGeneration(d['device'].read('idfwvs', 'single', extract=True))
				if current_gen in broadcast_firmware_generations and d['device'] not in all_broadcast_devices:
					d['args']['broadcast'] = True
					d['args']['fw'] = broadcast_firmwares[broadcast_firmware_generations.index(current_gen)]
					d['args']['collateral'] = True
					value['devices'].append(d)

				# Enable deep mode on all targets if one of the devices in ring is classic
				if current_gen == 'classic':
					for deviceDict in value['devices']:
						deviceDict['args']['deep'] = True

		# Filter out hybrids that are overridden by broadcast
		all_hybrids_fast_chip_ids = [x['device'].read('idchip', 'single', extract=True) for x in all_hybrids_fast]
		# Iterate all devices in all interfaces
		for ip, value in scheme.items():
			for deviceDict in value['devices']:
				try:
					# Search for current chip_id in all_hybrids_fast_chip_ids
					search = all_hybrids_fast_chip_ids.index(deviceDict['device'].read('idchip', 'single', extract=True))
					hybrid_match = all_hybrids_fast[search]
					if deviceDict is hybrid_match:
						continue

					# Current device broadcast overrides hybrid fast device
					if deviceDict['args']['broadcast'] == True:
						hybrid_match['args']['incompatible'] = True

				except ValueError:
					pass

		return scheme

	# Converts a FWUScheme to a simplified version
	# eg. multiple devices in same interface with broadcast update to same version
	# will be turned into 1 device, collaterals and incompatible upgrades are removed
	# and direct upgrades are removed if a broadcast overrides them.
	def filterFWUScheme(self, scheme):
		for ip, value in scheme.items():
			updates = []
			to_delete = []
			current_interface_args = value['args']

			# Sort devices so that broadcast updates come first
			value['devices'].sort(key=lambda x: x['args']['broadcast'], reverse=True)

			for deviceDict in value['devices']:
				current_device = deviceDict['device']
				current_device_args = deviceDict['args']

				isCollateral = ('collateral' in current_device_args and current_device_args['collateral'] is True)
				isIncompatible = ('incompatible' in current_device_args and current_device_args['incompatible'] is True)

				# Delete if device is collateral or imcompatible with new FW
				if isCollateral or isIncompatible:
					to_delete.append(deviceDict)
					continue

				# Delete if duplicate broadcast or broadcast overrides direct
				firmware_version = current_device_args['fw'][0]

				# Seach updates list for overrides
				if (firmware_version, True) in [(x['args']['fw'][0], x['args']['broadcast']) for x in updates]:
					to_delete.append(deviceDict)
				else:
					updates.append(deviceDict)

			for deviceDict in to_delete:
				value['devices'].remove(deviceDict)

		return scheme

	def removeCollateralsFWUScheme(self, scheme):
		for key, value in scheme.items():
			index = 0
			to_remove = []
			for deviceDict in value['devices']:
				if 'collateral' in deviceDict['args'] and deviceDict['args']['collateral'] is True:
					to_remove.append(index)
				index += 1
			to_remove.reverse()
			for r in to_remove:
				del value['devices'][r]
		return scheme

	# Checks if a given devices can be upgraded to a certain firmware version
	def isCompatible(self, device, firmware):
		current_fw = device.read('idfwvs', 'single', extract=True)
		target_fw = firmware[0]
		# No gateways
		if isinstance(device, Gateway):
			return False
		# Check if source and target FW are of the same generation
		if HLAPIHelper.firmwareToGeneration(current_fw) != HLAPIHelper.firmwareToGeneration(target_fw):
			return False
		# FW 204 and 206 to FW 200 -> 206 have no IPAPI support?
		if current_fw >= 204 and current_fw <= 206 and target_fw >= 200 and target_fw <= 206:
			return False
		# Six slave controllers need minimim 244
		if current_fw >= 244 and target_fw < 244 and device.read('cfsltp', 'single') == 1:
			return False
		# hPDU_G3 and DPM27/e need mimimum 250
		if (isinstance(device, hPDU_G3) or isinstance(device, DPM27e)) and target_fw < 250:
			return False
		return True
