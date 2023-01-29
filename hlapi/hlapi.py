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
import sys
import getopt
import importlib
import ast
import time
import threading
from collections import OrderedDict
import json

# Local imports
from . Helper import Helper as HLAPIHelper
from . spdm.RegisterHelper import RegisterHelper
from . DeviceManager import DeviceManager
from . managers.MultiReadWrite import MultiReadWrite
from . NetworkScanner import NetworkScanner

class HLAPI():
	"""
	This class handles HLAPI configuration and command line argument parsing if needed.
	"""

	DEFAULT_CONFIG = {
		'ipapi_timeout':	5,
		'ipapi_yield':		0.1,
		'ipapi_port':		7783,
		'webapi_timeout':	5,
		'scan_timeout':		12,
		'cache_expire':		1000,
		'file_compat_nr':	6,
		'downshift_tries':	5,
		'max_threads':		52,
		'presets': OrderedDict({
			'Identification': ['idspdm', 'idfwvs', 'idonbr', 'idpart', 'idsnbr', 'idchip', 'idaddr', 'idfwbd', 'idmaca', 'idspdt'],
			'Settings': ['stdvnm', 'stdvlc', 'stuser', 'stpkdr', 'strsal', 'stextn', 'stfodl', 'stpsav', 'stopom', 'stmaxt', 'stdiso', 'stimcm', 'stomcm', 'stomct', 'stimct', 'stinnm', 'stolnm', 'stiodl', 'stcddt', 'stsnsa', 'stunlo', 'strebt', 'starsa'],
			'Configuration': ['cfnrph', 'cfnrno', 'cfnrso', 'cfnrmo', 'cfamps'],
			'Measurements': ['imkwht', 'imkwhs', 'impfac', 'imcrac', 'imcrpk', 'imvoac', 'imvodp', 'imwkhf', 'omkwht', 'omkwhs', 'ompfac', 'omcrac', 'omcrpk', 'omvoac', 'omuwhs'],
			'Sensors': ['pditem', 'pdetem', 'pdinpk', 'pdexpk', 'snstyp', 'snsval', 'snsnme', 'snsenm']
		}),
	}

	DEFAULT_PROTOCOL_ORDER = ['WEBAPI', 'IPAPI']

	def __init__(self, configPath='', debug=False):
		self.config = None
		self.configPath = configPath
		self.debug = debug
		self.initConfig()

	def initConfig(self):
		datafile = os.path.join(self.configPath, 'hlapi_config.json')
		data = None

		if os.path.isfile(datafile):
			try:
				with open(datafile, "r") as f:
					data = json.load(f, object_pairs_hook=OrderedDict)
			except Exception as e:
				if self.debug: print("Could not load HLAPI config data file:", e)
				self.resetConfig()
				return

		if data is None:
			if self.debug: print("HLAPI config data file does not exist.")
			self.resetConfig()
			return
		else:
			if self.debug: print('Loaded config data file')
			for key in HLAPI.DEFAULT_CONFIG.keys():
				if key not in data:
					if self.debug: print('HLAPI config key', key, 'does not exist in local config, copying from defaults...')
					data[key] = HLAPI.DEFAULT_CONFIG[key]

			self.writeConfig(data)

	def resetConfig(self):
		config = HLAPI.DEFAULT_CONFIG
		self.writeConfig(config)

	def writeConfig(self, data):
		if self.config is None:
			self.config = data
		else:
			self.config = HLAPIHelper.dictMerge(self.config, data)
		if self.debug: print("Writing config...")

		datafile = os.path.join(self.configPath, 'hlapi_config.json')
		if self.config is not None:
			try:
				with open(datafile, "w") as f:
					json.dump(self.config, f)
				if self.debug: print('Saved config data file')
				return True
			except:
				print('Could not save config data file')
		return False

	def getConfig(self, record=None):
		if record is not None:
			val = self.config.get(record, None)
			if val is None and record in HLAPI.DEFAULT_CONFIG.keys():
				self.config[record] = HLAPI.DEFAULT_CONFIG.get(record, None)
				self.writeConfig(self.config)
				return self.config[record]
			return val

		return self.config

# Prints percentage until task is done
def showPercentage(progressManager, silent):
	progressManager.waitForInit()
	last_percentage = 0
	if not silent: print("0%")
	while progressManager.isRunning():
		percentage = progressManager.getStatus()[1]
		if percentage > last_percentage+10:
			if not silent: print(str(percentage)+"%")
			last_percentage = percentage
		time.sleep(0.1)
	if not silent: print("100%")
	progressManager.closeThreads()

# Convert Python dictionary to JSON
def returnResult(result, pretty):
	if pretty:
		print(json.dumps(result, indent=4))
	else:
		print(json.dumps(result))
	sys.exit(0)

def parseReadInput(input): # mnem,menm,mnem
	result = []
	splitted = input.split(',')
	for mnemonic in splitted:
		result.append(mnemonic)
	return result # [mnem, mnem, mnem]

def parseWriteInput(input): # mnem=v,menm=v,mnem=v
	result = {}
	splitted = input.split(',')
	try:
		for pair in input.split(','):
			k, v = pair.split('=')
			result[k] = RegisterHelper.formatData(RegisterHelper.registerLookup(k), v)
	except Exception as e:
		return None
	return result # {'mnemonic':'value', 'menmonic':'value', 'mnemonic':'value'}

def commandLine(argv):
	debug = False
	silent = False
	pretty = False
	read = None
	write = None
	targetPath = None

	# Parse command line arguments
	# -t target JSON file path (required)
	# -r "read", comma separated list of register mnemonics (x,x,x)
	# -w "write", comma separated list of register mnemonics and associated values (x=y,x=y,...)
	# -s (silent mode, only outputs result)
	# --pretty (pretty-prints json output to console)
	# --debug (enables HLAPI debug mode)
	try:
		opts, args = getopt.getopt(sys.argv[1:], "t:r:w:s", ['debug', 'pretty'])
	except getopt.GetoptError:
		print('Invalid arguments')
		sys.exit(0)

	for opt, arg in opts:
		if opt == '-t':
			targetPath = arg
		elif opt == '-r':
			read = arg.lower()
		elif opt == '-w':
			write = arg
		elif opt == '-s':
			silent = True
		elif opt == '--debug':
			debug = True
		elif opt == '--pretty':
			pretty = True

	if debug: silent = False
	targets = None

	# Load targets from path
	try:
		data = json.load(open(targetPath))
		targets = HLAPIHelper.organizeInterfaces(data)
		if not silent: print("Filtered out", len(data.keys())-len(targets.keys()), "interfaces (duplicate entries)")
	except:
		print('Input JSON error')
		sys.exit(0)

	if read is not None and write is None:
		# Prepare read operation
		register_data = parseReadInput(read)
	elif read is None and write is not None:
		# Prepare write operation
		register_data = parseWriteInput(write)
	else:
		print('Invalid Read/Write input')
		sys.exit(0)

	if register_data is None:
		print('Could not parse input')
		sys.exit(0)

	# Convert SUBNETS in input to IPs
	hlapi = HLAPI(debug=debug)
	scannedIPs = []
	# Targets is now a dict containing SUBNETS, IPs and DIRECT (IP#UNIT)
	subnets = {k:v for (k, v) in targets.items() if '*' in k}

	# Scan each subnet
	for interface, parameters in subnets.items():
		if not silent: print("Scanning (network)", interface)

		ns = NetworkScanner(hlapi, interface, parameters['webapi_port'], parameters['webapi_user'])
		if ns.inputAccepted:
			ns.startScan()
		else:
			break

		showPercentage(ns.progress, silent)

		if ns.progress.isAborted() or ns.progress.isError():
			result = {
				'status': 'fail',
				'message': 'An error occured while network scanning.',
				'unknown_devices': None,
				'renumber_devices': None
			}
			returnResult(result, pretty)

		elif ns.progress.isDone():
			data = ns.getResult()
			if not silent: print(interface, "->", data)
			if data is not None:
				scannedIPs += data

	# Remove SUBNETS from targets (replace by scanned IPs with same credentials)
	targets = HLAPIHelper.subnetsToIPs(targets, scannedIPs)

	# Start device identifcation
	deviceManager = DeviceManager(hlapi)
	deviceManager.startLoadInterfaces(targets)

	error = False
	unknownDevices = None
	renumberDevices = None

	if not silent: print("Identifying / scanning (databus)", len(targets.keys()), "targets")
	p = deviceManager.progress
	showPercentage(p, silent)

	if p.isAborted() or p.isError():
		result = {
			'status': 'fail',
			'message': 'An error occured during device identification.',
			'unknown_devices': None,
			'renumber_devices': None
		}
		returnResult(result, pretty)

	if p.isDone():
		# List of targets (IPs and/or direct devices is now converted to a list of Device objects)
		devices = deviceManager.getResult('raw')
		renumberDevices = deviceManager.result[3]
		unknownDevices = deviceManager.unknownDevices
		if not silent: print("Found", len(devices), "devices")

		if len(renumberDevices) > 0:
			# Fail when one or more devices need to be renumbered
			result = {
				'status': 'fail',
				'message': 'Some devices could not be identified or need to be renumbered.',
				'unknown_devices': ["#".join([str(x), str(y)]) for x,y in unknownDevices],
				'renumber_devices': ["#".join([str(x), str(y)]) for x,y in renumberDevices]
			}
			returnResult(result, pretty)

		else:
			# Read the required registers from all devices
			if not silent: print("Executing...")
			multiReadWrite = MultiReadWrite(hlapi, devices)
			if read is not None:
				multiReadWrite.readAll(register_data, block=False)
			elif write is not None:
				write_model = {x.getUid():register_data for x in devices}
				multiReadWrite.writeAll(write_model, block=False)

			p = multiReadWrite.progress
			showPercentage(p, silent)

			if p.isAborted() or p.isError():
				result = {
					'status': 'fail',
					'message': 'An error occured in MultiReadWrite.',
					'unknown_devices': None,
					'renumber_devices': None
				}
				returnResult(result, pretty)

			if p.isDone():
				result = {
					'status': 'ok',
					'data': HLAPIHelper.makeOrdered(multiReadWrite.result),
					'unknown_devices': ["#".join([str(x), str(y)]) for x,y in unknownDevices],
					'renumber_devices': ["#".join([str(x), str(y)]) for x,y in renumberDevices]
				}
				returnResult(result, pretty)

if __name__ == "__main__":
	commandLine(sys.argv[1:])
