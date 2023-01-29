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
import hashlib
import hmac
import socket
import struct
import time
import urllib
# import requests

# Local imports
from .. Helper import Helper as HLAPIHelper
from .. spdm.RegisterHelper import RegisterHelper
from .. spdm.Registers import *

# Library imports
from .. library import requests

# Helper class for maintaining the connection
class WebApiSync:
	def __init__(self, uptime, userid, username, password):
		self.boottime = None
		self.userid = userid
		self.username = username
		self.password = password

		self.set_uptime(uptime)

	def get_uptime(self):
		# Calculate PDU's uptime
		return int(time.time()) - self.boottime

	def set_uptime(self, uptime):
		# Calculate PDU's time-of-boot in terms of this computer's time
		self.boottime = int(time.time()) - uptime

	def token_raw(self, uptime, userid, username, password):
		# sanitize
		uptime = int(uptime)
		userid = int(userid)
		username = str(username)
		password = str(password)
		# generate signature
		userkey = username + ":" + password # HMAC secret
		message = uptime * 8 + userid # 32 bit integer, lowest 3 bits are userid, highest 29 bits are nonce
		signature = hmac.new(userkey.encode('utf-8'), struct.pack('>I', message), hashlib.sha256).hexdigest()
		messagehex = '%08x' % (message)
		signature = signature[:8]
		token = '%s%s' % (messagehex, signature)

		return token

	def token(self):
		return self.token_raw(self.get_uptime(), self.userid, self.username, self.password)

class WEBAPIProtocol(object):

	HTTPSTATUS_MAP = {
			200: 'OK',
			401: 'ERR_AUTH',
			403: 'ERR_FORBIDDEN',
			404: 'ERR_NOTFOUND',
			422: 'ERR_REJECTED',
			500: 'ERR_INTERNAL'
	}

	def __init__(self, hlapi_instance, ip, params):
		self.hlapi = hlapi_instance
		self.ip = ip
		self.port = params['webapi_port']
		self.username = params['webapi_user']
		self.password = params['webapi_pass']
		self.conn = False
		self.invalidCredentials = False
		self.sync = None
		self.timeout = self.hlapi.getConfig('webapi_timeout')
		self.requestsSession = requests.Session()
		self._resync()

	# Refreshes the http connection to a device
	def _resync(self):
		# remove synchronization first
		self.sync = None
		self.conn = True
		# also make sure old keep-alive connections are not used anymore
		# -- device might have been intentionally rebooted if user tries to resync
		self.requestsSession = requests.Session()

		starttime = time.time()
		# Try and post the /userid value, refer to WEBAPI documentation.
		response = self._request_internal('POST', '/userid', {'user': self.username})
		if response is not None:
			if response[2] == 200: # 200/OK
				if 'userid' in response[0] and 'time' in response[0]:
					self.sync = WebApiSync( int(response[0].get('time')), int(response[0].get('userid')), self.username, self.password )
					# Great success, version is 2.14
					elapsedTime = (time.time()-starttime)
					if self.hlapi.debug: print("WEBAPI connection with", self.ip, "@", self.port, "established after", elapsedTime, "seconds")
					return
		self.conn = False

	# Performs a POST or GET request
	# Input:	method: POST or GET
	#			uri: request url
	#			params: POST or GET data in a dictionary
	#			unit: a unit address, if given, bridging-over-databus must be supported for the
	#				given request. Refer to the WEBAPI documentation for more info.
	# Output:	A tuple with the result status code and data
	def _request_internal(self, method='POST', uri='/', params=None, unit=None, timeoutOverride=None):
		# Prepare url and parameters
		if not self.conn:
			return None

		if params is None:
			params = {}

		if uri[0] != '/':
			uri = '/' + uri

		uri = self._get_bridge_prefix(unit) + uri
		if self.ip.find(":") != -1:
			self.ip = '['+str(self.ip)+']'
		url = 'http://%s:%d%s' % (self.ip, self.port, uri)

		headers = {}
		data = None

		# Check if we still have a connection
		if self.sync:
			token = self.sync.token()
			headers['Authorization'] = 'hPDU-auth-v1 %s' % (token)

		# Encode input data if POST is used
		if method == 'POST':
			data = urllib.parse.urlencode( params )
			headers['Content-type'] = 'application/x-www-form-urlencoded'

		timeout = self.timeout
		if timeoutOverride is not None:
			timeout = timeoutOverride

		stitched = b''
		# Do request
		try:
			if method == 'POST':
				response = self.requestsSession.post(url, timeout=timeout, headers=headers, stream=True, data=data)
			else:
				response = self.requestsSession.get(url, timeout=timeout, headers=headers, stream=True, data=data)

			for chunk in response.iter_content(chunk_size=None):
				stitched += chunk

		except (requests.exceptions.RequestException, socket.error, socket.timeout) as e:
			if isinstance(e, requests.exceptions.Timeout) or isinstance(e, socket.error) or isinstance(e, socket.timeout):
				return 'TIMEOUT'
			else:
				if self.hlapi.debug: print(e)
			return ('', self.HTTPSTATUS_MAP[500], None)

		httpcode = response.status_code
		data = {}
		if 'content-type' in response.headers and response.headers['content-type'] in ['text/plain', 'application/x-www-form-urlencoded']:
			data = urllib.parse.parse_qs(stitched.decode("utf-8"), True)
			for key in list(data.keys()):
				data[key] = data[key][-1]  # keep last value if an item is mentioned multiple times

		resultcode = None
		if 'result' in data:
			resultcode = data['result']
			del data['result']
		elif httpcode in self.HTTPSTATUS_MAP:
			resultcode = self.HTTPSTATUS_MAP[httpcode]
		else:
			resultcode = self.HTTPSTATUS_MAP[500] # fallback to internal error

		if resultcode == 'ERR_AUTH':
			if self.hlapi.debug: print("Invalid auth")
			self.invalidCredentials = True
			self.conn = False

		# Return result
		return (data, resultcode, httpcode)

	# Return a URL prefix for bridging-over-databus
	# Warning: BoD only works for registers that can be sent over databus, so WEBAPI-only registers cannot be bridged over databus.
	def _get_bridge_prefix(self, unit):
		if unit is None:
			return ''

		return '/databus/{0}'.format(unit)

	# For reading or writing to a specific register, add a prefix to the request url
	# if the given register has more than 1 repeat, add a suffix to the url with the number of repeats.
	# Input:	register: register instance
	# Output:	'/register/number_of_repeats_if_more_than_1'
	def _prepRegUrl(self, register):
		url = '/register/'+str(register.Mnemonic)
		if (register.Repeats > 1):
			url += '/'+str(register.Repeats)
		return url

	# The WEBAPI formats registers with repeats as key-value pairs like so: register_mnemonic_repeat_number:value
	# For writing to a register, the input data needs to be converted from a list with values only
	# to a key-value dictionary
	# Input:	register: a register instance
	#			data: a list of values, length of this list should match the number of register repeats
	# Output:	A dictionary of mnemonic_repeat:value pairs or a single mnemonic:value pair depending on the
	#			number of register repeats.
	def _composeRegisterRepeats(self, register, data):
		if register.Repeats > 1:
			result = {}
			for i in range(1, register.Repeats+1):
				result[str(register.Mnemonic)+'_'+str(i)] = data[i-1]
		else:
			result = {register.Mnemonic:data}
		return result

	# The WEBAPI returns multiple registers and registers with repeats using key-value pairs in a dictionary.
	# Each register repeat must be converted to a single mnemonic:[repeat_value_1, repeat_value_2, ...] dictionary.
	# In order to match register channels with repeat values we need to sort the input dictionary based on it's keys.
	# Input:	inputDict: A dictionary with register names as keys (or register names with a _repeat_num suffix)
	#					and their corresponding values.
	#			mnemonics: The register mnemonics in which to parse the input dictionary
	# Output:	A standardised mnemonic:value or mnemonic:[value1, value2, ...] dictionary
	def _dictChannelSort(self, inputDict, mnemonics):
		# Prepare result dict by initialising each given mnemnic with an empty list as value
		result = {}
		for mnemonic in mnemonics:
			result[mnemonic] = []

		# Iterate input dictionary keys (either register mnemonics or register mnemonics with _repeat_num suffix)
		keys = list(inputDict)
		for key in keys:
			parsed = key.split('_')
			mnemonic = str(parsed[0])
			if len(parsed) > 1:
				# If input key:value pair is a repeat register
				channel = int(parsed[-1])
				if mnemonic in result:
					# Extend result for this register with the parsed channel number
					result[mnemonic].append(channel)

		for mnemonic in mnemonics:
			# The result dictionary currently contains mnemonics as keys and empty list or channel numbers as values
			register_channels = result[mnemonic]
			# Sort the current value
			register_channels.sort()
			# register_channels = dict(mnem1:[c1, c2, ..], mnem2:[c1, c2, ..], mnem3:[c1, c2, ..])

			# If the input dictionary has the current mnemonic as key, this means the register has NO
			# repeats. Otherwise the input dictionary would have registerMnemonic_repeatNumber as keys.
			if mnemonic in inputDict:
				# No repeats, single value, deserialize and append to result
				data = inputDict[mnemonic]
				data = self._deserialize(data, RegisterHelper.registerLookup(mnemonic))
			else:
				sorted_data = []
				num_channels = len(register_channels)

				if num_channels == 0:
					sorted_data = None
				else:
					# Iterate the (now sorted) register channels
					for i in range(num_channels):
						# Deserialize value and append to result
						value = self._deserialize(inputDict.get(str(mnemonic)+'_'+str(register_channels[i])), RegisterHelper.registerLookup(mnemonic))
						sorted_data.append(value)

				data = sorted_data

			# Replace channel numbers by their corresponding input dictionary values
			result[mnemonic] = data

		return result

	# Deserializes a value depending on the type of register the value belongs to
	# A deserialized value should be human readable
	def _deserialize(self, data, register):
		regType = register.Type
		try:
			if regType == ASCII:
				try:
					data = str(data)
					i = data.find('\0')
					if i != -1:
						data = data[:i]

					result = HLAPIHelper.removeControlChars(data)
				except Exception as e:
					if self.hlapi.debug: print("WEBAPIProtocol STR decode error:", e)
					result = 'DECODE_ERR'

				return result
			elif regType == IPV4 or regType == IPV6:
				return str(data)
			elif regType == FD:
				return float(data)
			elif regType == INT:
				if register.RegisterLength == 6:
					# MAC address exception
					return str(data).lower()
				return int(data)
			else:
				if self.hlapi.debug: print("Unrecognised register type:", regType)
		except Exception as e:
			if self.hlapi.debug: print("Parsing of register", register.Mnemonic, "failed! (WEBAPIProtocol)", "Data: "+str(data), "Error:", e)
			return None

	# Read a single register from a specific unit
	# Input:	register: register instance
	#			unit: unit address
	# Output:	Dictionary with mnemonic:value pair(s) or None on fail
	def readRegister(self, register, unit):
		url = self._prepRegUrl(register)
		reply = self._request_internal(method='GET', uri=url, unit=unit)
		if reply is not None:
			if reply == 'TIMEOUT':
				return 'TIMEOUT'
			elif reply[1] == 'OK':
				try:
					return {register.Mnemonic:self._deserialize(reply[0][register.Mnemonic], RegisterHelper.registerLookup(register.Mnemonic))}
				except:
					return self._dictChannelSort(reply[0], [register.Mnemonic])
			else:
				return None
		else:
			return None

	# Write data to a single register on a specific unit
	# Input:	register: a register instance
	#			unit: a unit address
	#			data: validated data to be written to the given register
	# Output:	True on success, False on fail
	def writeRegister(self, register, unit, data):
		url = self._prepRegUrl(register)
		params = self._composeRegisterRepeats(register, data)
		reply = self._request_internal(method='POST', uri=url, params=params, unit=unit)
		if reply is not None:
			if reply == 'TIMEOUT':
				return 'TIMEOUT'
			elif reply[1] == 'OK':
				return True
			else:
				return False
		else:
			return False

	# Reads a group of registers
	# Input:	registers: a list of register instances
	#			groupName: the name of the SPDM group to read
	#			unit: unit address
	# Output:	A dictionary of mnenonic(_repeats):value(s) pair(s) or None on fail
	def readGroup(self, registers, groupName, unit):
		url = '/group/'+str(groupName)
		reply = self._request_internal(method='GET', uri=url, unit=unit)

		if reply is not None:
			if reply == 'TIMEOUT':
				return 'TIMEOUT'
			elif reply[1] == 'OK':
				registerMnemonics = []
				if reply[0] == {}:
					return None
				for register in registers:
					registerMnemonics.append(register.Mnemonic)
				return self._dictChannelSort(reply[0], registerMnemonics)
			else:
				return None
		else:
			return None

	# Writes data to a group
	# Input:	registers: a list of register instances
	#			groupName: the SPDM group name to which we write
	#			unit: unit address
	#			data: a list of validated values, each given register should have a corresponding value
	#			writeStatus: a boolean list, true or false for each given register only registers that
	#						have a matching True will be written to. This registers writeStatus will be
	#						updated with True or False depending on write success or fail.
	# Output:	The given writeStatus, the items with True as value have been updated with the write status.
	def writeGroup(self, registers, groupName, unit, data, writeStatus):
		for register in registers:
			if writeStatus[register.Mnemonic]:
				writeStatus[register.Mnemonic] = self.writeRegister(register, unit, data[register.Mnemonic])
		return writeStatus

	def updateCredentials(self, credentials):
		currentUserID = self.sync.userid
		result = []
		level = 0
		for login in credentials:
			if login is not None and str(login[0]).lower() != 'none':
				if login[0] == "DISABLED":
					login = ("", None)

				data = {
					'userid': level+1,
					'username': login[0],

				}
				# Change password if password is given and username is not empty
				# A user can be disabled by leaving it's associated channel blank
				if len(str(login[0])) > 0 and str(login[1]).lower() != 'none' and len(str(login[1])) > 0:
					data['chpasswd'] = 1
					data['password'] = login[1]

				returnVal = self.sendRaw('/save/user', 'POST', data=data)

				if returnVal is not None and returnVal[1] == 'OK':
					result.append(True)
					# Update internal credentials if current user is changed
					if level == currentUserID:
						self.username = login[0]
						if 'chpasswd' in data:
							self.password = login[1]
						self._resync()
				else:
					result.append(False)
			level += 1

		return result

	# Sends a raw request, this is just a wrapper function for _request_internal but implemented
	# for consistency with the IPAPI protocol sendRaw()
	def sendRaw(self, url, method, unit=None, data={}, timeoutOverride=None):
		reply = self._request_internal(method=method, uri=url, params=data, unit=unit, timeoutOverride=timeoutOverride)
		if reply is not None:
			if reply == 'TIMEOUT':
				return 'TIMEOUT'
			elif reply[1] == 'OK':
				return reply
			elif 'address' in url and reply[1] == 'ERR_REJECTED':
				# PDU WEBAPI unit address change bug workaround
				if self.hlapi.debug: print("WEBAPI unit address change response is ERR_REJECTED, assuming OK.")
				return reply
		return None
