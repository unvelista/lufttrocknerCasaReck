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
import errno
import re
import select
import socket
import time
import logging

# Local imports
from .. Helper import Helper as HLAPIHelper
from .. spdm.RegisterHelper import RegisterHelper
from .. spdm.Registers import *
from . IPAPIFramer import *

# Library imports
from .. library.arc4 import *

class IPAPIProtocol(object):

	RECONNECT_ERRORS = [
		errno.EHOSTUNREACH,
		errno.EHOSTDOWN,
		errno.ENETDOWN,
		errno.ENETUNREACH,
		errno.EPROTO,
		errno.EBADMSG,
		errno.ECONNREFUSED,
		errno.ECONNABORTED,
		errno.ENOTSUP,
		errno.ENOTCONN,
		errno.EPIPE,
		errno.EFAULT,
		errno.ECONNRESET,
		errno.ETIMEDOUT
	]

	def __init__(self, hlapi_instance, ip, params):
		self.ip = ip
		self.hlapi = hlapi_instance
		self.port = self.hlapi.getConfig('ipapi_port')
		self.timeout = self.hlapi.getConfig('ipapi_timeout')
		self.yieldSeconds = self.hlapi.getConfig('ipapi_yield')

		self.conn = False
		self.sock = None
		self.yieldTime = 0
		self.passOn = b''

		self.username = None
		self.key = params['ipapi_key']
		if not (isinstance(self.key, str) and len(self.key) == 16):
			if self.hlapi.debug: print("Invalid RC4 key for", self.ip)
			return

		self._openSocket()
		f = self._composeFrame('read', 102, 2, unit=0, layer=0)
		self.writeRaw(f)
		reply = self.readRaw(timeoutOverride=None, reWriteOnEmpty=True)
		if reply == 'TIMEOUT':
			self.conn = False
		# self._closeSocket()

	# Open the socket
	def _openSocket(self, elapsedTime=0):
		self._closeSocket()

		if self.yieldTime > 0:
			time.sleep(self.yieldTime)
			self.yieldTime = 0

		self.conn = False
		starttime = time.time()
		ip_mode = HLAPIHelper.parseIP(self.ip)

		if self.hlapi.debug: print("Opening socket to", self.ip, "...")
		try:
			if ip_mode == 'IPv4':
				af = socket.AF_INET
			elif ip_mode == 'IPv6':
				af = socket.AF_INET6
			else:
				if self.hlapi.debug: print("Could not parse IP", self.ip)
				return self.conn

			self.sock = socket.socket(af, socket.SOCK_STREAM)
			info = socket.getaddrinfo(self.ip, self.port, af, socket.SOCK_STREAM)
			self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.sock.settimeout(self.timeout)
			self.sock.connect( info[0][4] )
			self.sock.settimeout(0.0) # = non-blocking
			self.conn = True
			elapsedTime += time.time() - starttime
			if self.hlapi.debug: print("IPAPI connection with", self.ip, "@", self.port, "established after", elapsedTime, "seconds")

		except socket.error as e:
			elapsedTime += time.time() - starttime
			if e.errno in IPAPIProtocol.RECONNECT_ERRORS or elapsedTime >= self.timeout:
				if self.hlapi.debug: print("Could not connect to", self.ip, "@", self.port, e, "elapsedTime:", elapsedTime)
				self.conn = False
				self._closeSocket()
			else:
				if self.hlapi.debug: print(self.ip, "@", self.port, "socket open fail", e, "retry... Error message:", e)
				time.sleep(0.1)
				return self._openSocket(elapsedTime=elapsedTime)


		return self.conn

	def __del__(self):
		self._closeSocket()

	def _closeSocket(self):
		if self.sock is None:
			return
		# Try sending something to check connection, if connected, shutdown
		try:
			self.sock.send(1)
			self.sock.shutdown(socket.SHUT_RDWR)
			if self.hlapi.debug: print("Shut down socket", self.ip)
		except:
			pass
		self.sock.close()
		self.conn = False

	def _flushSocket(self):
		if self.sock is None:
			return
		while True:
			try:
				reply = self.sock.recv(1024)
				if not reply or reply == b'' or len(reply) == 0:
					break
				if self.hlapi.debug: print("Flushed incoming socket data length =", len(reply))
			except:
				break

	# Checks if there is a Schleifenbauer gateway on the other side of the socket
	# Register 102->104 is the only register a gateway can respond to.
	# Unit address 0 = default for gateway
	def isGateway(self):
		f = self._composeFrame('read', 102, 2, unit=0)
		response = self.broadcast(f, collect=True, collectTimeout=5)
		if response == 'TIMEOUT':
			return 'TIMEOUT'
		if len(response) > 0:
			value = response[0].findField(DATA).value
			if len(value) > 0:
				fw_version = self._deserialize('idfwvs', value)
				if (fw_version == 18263):
					return True
		return False

	# Sets a specific device's unit address (identified using a hardware address) using IPAPI specifically
	# Warning: Using this function directly requires updating a device's associated unit address manually.
	#			AbstractDevice.setUnitAddress does take care of this.
	def setUnitAddress(self, hid, value):
		self._flushSocket()
		# Compose unit address change SPBUS frame
		f = Frame()
		f.Fields = SetAddressFields
		f.setField(COMMAND, f.CMD_SETADDRESS[0])
		f.setField(HARDWAREID, hid)
		f.setField(UNITADDRESS, value)
		# Write the frame to the specified device
		reply = self.writeRaw(f)

		if reply == 'TIMEOUT':
			return 'TIMEOUT'
		elif reply == False:
			return None

		# Fetch the response
		response = self.readRaw(reWrite=f)

		# If the response has size 1, it's an SPBUS error code (not NAK)
		if response is None or len(response) < 1:
			if self.hlapi.debug: print("SPBUS error")
			return None

		if response == 'TIMEOUT':
			return True # TODO: this a temporary bug workaround, the ring master PDU
						# expects the PDU with the new address to return an ACK associated
						# with the old unit address, however, the new address is attached
						# to the databus packet.
			#return 'TIMEOUT'

		# Check if response is a NAK message
		if response[0].findField(STARTBYTE).value in response[0].NAK:
			if self.hlapi.debug: print("Unit address change NAK")
			return None

		return True

	# Switches all displays on behind this interface on or off using IPAPI specifically
	# input:	state: 0=off, 1=on
	def setDisplays(self, state):
		# if ipapi is not None:
		#	f = Frame()
		#	if state == 1:
		#		f.Fields = DisplaysOnFields
		#		f.setField(COMMAND, f.CMD_DISPLAYON[0])
		#	else:
		#		f.Fields = DisplaysOffFields
		#		f.setField(COMMAND, f.CMD_DISPLAYOFF[0])
		#	reply = ipapi.writeRaw(f)
		#	return reply
		# return False
		pass

	# Reads a register from a given unit
	# Input:	register:	Register
	#			unit:		Unit address
	# Output:	Single-item dictionary with the register's mnemonic as key and a single value or a list as value,
	#			depending on the number of repeats for the given register.
	def readRegister(self, register, unit):
		self._flushSocket()

		reg_location = register.RegisterStart
		reg_length = register.RegisterLength
		reg_repeats = register.Repeats

		result = []

		# If the register uses an extended layer, read from both
		extendedRead = 0
		if register.Extension:
			extendedRead = 1

		for i in range(extendedRead+1):
			# Compose SPBUS read frame depending on the given register, unit and layer
			f = self._composeFrame('read', reg_location, reg_length*reg_repeats, unit=unit, layer=i)
			self.passOn = b''
			# Write the read request frame to the SPBUS
			logging.info("PROTOCOLS//IPAPI: writing frame to SPBUS:\n %s",	str(f))
			reply = self.writeRaw(f)
			if reply == 'TIMEOUT':
				# self._closeSocket()
				return 'TIMEOUT'

			response = None
			if reply is not False:
				# Fetch the response
				response = self.readRaw(reWrite=f)
				# self._closeSocket()
			else:
				# self._closeSocket()
				return None

			# If the response has size 1, it's an SPBUS error code (not NAK)
			if response is None or len(response) < 1:
				return None

			if response == 'TIMEOUT':
				return 'TIMEOUT'

			# Check if response is a NAK message
			if response[0].findField(STARTBYTE).value in response[0].NAK:
				return None

			# Append the response to the result
			result += response

		responseValueList = []
		# The result should consist of one or two frames (depending on whether the extedned layer has been read)
		# However, sockets being sockets, some data might have been buffered resulting in multiple frames per read
		for responseFrame in result:
			logging.info("PROTOCOLS//IPAPI: received response:\n %s",  str(responseFrame))
			# Extract data
			responseValue = responseFrame.findField(DATA).value
			# If the register has more than 1 repeat, the received data must be chopped up into equal parts
			responseValue = self._parseRepeats(responseValue, reg_length)
			for v in responseValue:
				# Deserialize the received data for each repeat and append to result
				value = self._deserialize(register.Mnemonic, v)
				responseValueList.append(value)

		# If a single frame has been received for a single repeat register, extract the value from the response list
		if len(responseValueList) == 1:
			responseValueList = responseValueList[0]

		return {register.Mnemonic:responseValueList}

	# Writes data to a register
	# Input:	register:	Register
	#			data:		string
	# Output:	None
	def writeRegister(self, register, unit, data):
		self._flushSocket()

		reg_location = register.RegisterStart
		reg_length = register.RegisterLength
		reg_repeats = register.Repeats

		# If the register uses an extended layer, write to both
		extendedRead = 0
		if register.Extension:
			extendedRead = 1

		# Turns the given registers and their corresponding write data into a serialized SPBUS command
		# If the given register doesn't use an extended layer, all data will be in layerData[0]
		layerData = self._composeRegisters([register], {register.Mnemonic:data})
		if layerData is None:
			return False

		for i in range(extendedRead+1):
			# Compose SPBUS write frame depending on the given register, unit, layer and data
			f = self._composeFrame('write', reg_location, reg_length*reg_repeats, unit=unit, layer=i, data=layerData[i])
			self.passOn = b''
			# Write the frame to the SPBUS
			logging.info("PROTOCOLS//IPAPI: writing frame: %s to SPBUS",  str(f))
			reply = self.writeRaw(f)
			if reply == 'TIMEOUT':
				return 'TIMEOUT'
			response = None
			if reply is not False:
				# Fetch the response (All devices return an ACK after a write, 'or so I think' -> TODO!)
				response = self.readRaw(reWrite=f)
				logging.info("PROTOCOLS//IPAPI: received response: %s",	 str(response))
			else:
				return False

			# If the response has size 1, it's an SPBUS error code (not NAK)
			if response is None or len(response) < 1:
				return False

			if response == 'TIMEOUT':
				return 'TIMEOUT'

			# Check if response is a NAK message
			if response[0].findField(STARTBYTE).value in response[0].NAK:
				if self.hlapi.debug: print('NAK received')
				return False

		return True

	# Reads a block of registers from a given unit
	# Input:	registers:	list of registers
	#			groupName:	the SPDM group name of the given registers
	#			unit:		unit address
	# Output:	Multi-item dictionary with the register mnemonics as keys and a single values or a lists as values,
	#			depending on the number of repeats for the each register.
	def readGroup(self, registers, groupName, unit):
		# Get the number of registers in the given group that use an extended layer
		self._flushSocket()
		numExtendedRegisters = len([x for x in registers if x.Extension])
		containsExtendedRegister = numExtendedRegisters != 0

		if len(registers) > 0:
			# Determine block dimensions
			start = registers[0].RegisterStart # Assuming registers are ordered by registerstart
			end = registers[-1].RegisterStart+(registers[-1].RegisterLength*registers[-1].Repeats)
			length = end-start

			result = None

			# If one of the registers uses an extended layer, read the extended layer as well.
			# Note that trying to read the extended layer for a group that doesn't contain a register
			# that uses the extended layer results in an error (NAK response). Reading the extended layer
			# for a group in which one or more registers make use of the extended layer without errors.
			extendedRead = 0
			if containsExtendedRegister:
				extendedRead = 1

			for i in range(extendedRead+1):
				# Compose SPBUS read frame depending on the given block, unit and layer
				f = self._composeFrame('read', start, length, unit=unit, layer=i)
				self.passOn = b''
				# Write the read request frame to the SPBUS
				logging.info("PROTOCOLS//IPAPI: writing frame: %s to SPBUS",  str(f))
				reply = self.writeRaw(f)
				if reply == 'TIMEOUT':
					return 'TIMEOUT'
				response = None
				if reply is not False:
					response = self.readRaw(reWrite=f)
					logging.info("PROTOCOLS//IPAPI: received response: %s",	 str(response))
				else:
					return None

				# If the response has size 1, it's an SPBUS error code (not NAK)
				if response is None or len(response) < 1:
					return None

				if response == 'TIMEOUT':
					return 'TIMEOUT'

				# The result should consist of a single frame
				# However, sockets being sockets, some data might have been buffered resulting in multiple frames
				# In the latter case: https://www.youtube.com/watch?v=0n_Ty_72Qds
				if len(response) == 1:
					# Check if response is NAK
					if response[0].findField(STARTBYTE).value in response[0].NAK:
						if self.hlapi.debug: print('NAK received')
						return None
					# Extract data from frame
					value = response[0].findField(DATA).value
					# Parse the group read data into individual registers. If this is the second (extended)
					# iteration, pass the previous layer's parsed result along in order to merge them together
					# into one dictionary
					if value is not None:
						result = self._parseRegisters(value, registers, result)
					else:
						if self.hlapi.debug: print("NONE: "+str(response))
				else:
					if self.hlapi.debug: print('Received multiple frames for a group read, cannot parse')
					return None

			return result
		else:
			if self.hlapi.debug: print('Not a group')
			return None

	# Writes a block of register data to a given unit
	# Input:	registers:	list of registers
	#			groupName:	the SPDM group name of the given registers
	#			unit:		unit address
	#			data:		list of input data corresponding with the given registers
	#			writeStatus:boolean list where each value is either a go or a no-go for the given registers.
	# Output:	the given writeStatus list, the registers where writeStatus[register] was true have had their
	#			data written to and writeStatus value changed to whether the write was successful.
	def writeGroup(self, registers, groupName, unit, data, writeStatus):
		#	Problemo
		#
		#	If a single register in a group/block isn't writable by the IPAPI,
		#	the PDU will stop writing, reverse all changes and return a NAK.
		#	This makes block writing incredibly inconvenient.
		#	As a solution, let's write to each register individually

		for register in registers:
			if writeStatus[register.Mnemonic]:
				# if self.hlapi.debug: print 'writing '+str(data[register.Mnemonic])+' ('+str(repr(self._serialize(data[register.Mnemonic], register)))+') (length '+str(len(self._serialize(data[register.Mnemonic], register)))+') to unit '+str(unit)+' register '+str(register.Mnemonic)
				writeStatus[register.Mnemonic] = self.writeRegister(register, unit, data[register.Mnemonic])
		return writeStatus

		#	Here's the code for a group block directly
		#
		# numExtendedRegisters = len([x for x in registers if x.Extension == 'true'])
		# containsExtendedRegister = numExtendedRegisters != 0
		#
		# layerData = self._composeRegisters(registers, data)
		# if len(registers) > 0:
		#	# Determine block
		#	start = registers[0].RegisterStart
		#	end = registers[-1].RegisterStart+registers[-1].RegisterLength
		#	length = end-start
		#	result = None
		#	extendedWrite = 0
		#	if containsExtendedRegister:
		#		extendedWrite = 1
		#
		#	if self.hlapi.debug: print 'Writing block:',start,length,extendedWrite,len(layerData[0])
		#	for i in range(extendedWrite+1):
		#		f = Frame()
		#		f.Fields = ReadRegisterFields
		#		f.setField(COMMAND, f.CMD_WRITE[i])
		#		f.setField(UNITADDRESS, unit)
		#		f.setField(REGISTERSTART, start)
		#		f.setField(REGISTERLENGTH, length)
		#		f.setField(DATA, layerData[i])
		#
		#		reply = self.writeRaw(f)
		#		if reply == False:
		#			if self.hlapi.debug: print 'write failed'
		#			return None
		#
		#		response = self._readRawTimeoutWrapper()
		#		if response is None or len(response) < 1:
		#			if self.hlapi.debug: print 'receive failed'
		#			return None
		#		if response[0].findField(STARTBYTE).value in response[0].NAK:
		#			if self.hlapi.debug: print 'NAK received'
		#			return None
		#
		# return writeStatus

	def broadcast(self, frame, collect=False, collectTimeout=None):
		if collect is True and collectTimeout is None:
			if self.hlapi.debug: print("No collect timeout given!")
			return []
		self.passOn = b''
		# Write frame onto SPBUS
		self._flushSocket()
		if self.hlapi.debug: print("Broadcasting frame to databus...")
		reply = self.writeRaw(frame)
		if reply == 'TIMEOUT':
			return 'TIMEOUT'
		if collect:
			collected = []
			if self.hlapi.debug: print("Collecting with timeout =", collectTimeout, "seconds...")
			starttime = time.time()
			elapsedTime = 0
			while (True):
				result = self.readRaw(reWrite=frame, reWriteOnEmpty=False)
				elapsedTime += (time.time() - starttime)
				if elapsedTime > collectTimeout:
					break
				if result == 'TIMEOUT':
					break
				elif result is not None:
					collected += result
			# self._closeSocket()
			if self.hlapi.debug: print("Total collected frames:", len(collected))
			return collected
		# else:
			# self._closeSocket()

	# Reads one or more frames from the socket
	# Input:	None
	# Output:	List(Frame)
	def readRaw(self, elapsedTime=0, timeoutOverride=None, reWrite=None, reWriteOnEmpty=True):
		if timeoutOverride is None:
			timeoutOverride = self.timeout

		starttime = time.time()
		if not self.conn:
			if self.hlapi.debug: print("No connection, aborting readRaw")
			return None

		result = None

		try:
			ready_to_read, ready_to_write, in_error = select.select([self.sock], [], [], 0)

			if len(ready_to_read) == 0:
				if self.conn and elapsedTime < timeoutOverride:
					time.sleep(0.1)
					elapsedTime += time.time() - starttime
					return self.readRaw(elapsedTime=elapsedTime, timeoutOverride=timeoutOverride, reWrite=reWrite, reWriteOnEmpty=reWriteOnEmpty)
				if self.hlapi.debug: print('Read timeout A.', elapsedTime, '(readRaw)')
				return 'TIMEOUT'

			for s in ready_to_read:
				if s == self.sock:
					maxsize = 4096
					reply = s.recv(maxsize)
					if not reply or reply == b'' or len(reply) == 0:
						if self.conn and elapsedTime < timeoutOverride:
							time.sleep(0.1)
							elapsedTime += time.time() - starttime
							if reWrite is not None and reWriteOnEmpty is True:
								if self.hlapi.debug: print('Resending write frame... (readRaw)')
								self._flushSocket()
								self.writeRaw(reWrite)
							return self.readRaw(elapsedTime=elapsedTime, timeoutOverride=timeoutOverride, reWrite=reWrite, reWriteOnEmpty=reWriteOnEmpty)

						if self.hlapi.debug: print('Read timeout.', elapsedTime, '(readRaw)')
						return 'TIMEOUT'

					result = reply

		except (socket.error, IOError, Exception) as e:
			if e.errno not in IPAPIProtocol.RECONNECT_ERRORS:
				if self.hlapi.debug: print(e, type(e))
				return 'TIMEOUT'
			if self.conn and elapsedTime < timeoutOverride:
				time.sleep(0.1)
				if self.hlapi.debug: print('Socket error:', e, 'Retry... (readRaw)')
				if e.errno in IPAPIProtocol.RECONNECT_ERRORS:
					self._openSocket()
				elapsedTime += time.time() - starttime
				if self.hlapi.debug: print("Elapsed time=", elapsedTime, "of", timeoutOverride)
				if reWrite is not None:
					if self.hlapi.debug: print('Resending write frame... (readRaw)')
					self._flushSocket()
					self.writeRaw(reWrite)
				return self.readRaw(elapsedTime=elapsedTime, timeoutOverride=timeoutOverride, reWrite=reWrite, reWriteOnEmpty=reWriteOnEmpty)
			if self.hlapi.debug: print('Socket error could not be resolved', elapsedTime, '(readRaw)')
			return 'TIMEOUT'

		self.yieldTime = self.yieldSeconds
		# Parse the incoming data into SPBUS messages
		if result is not None:
			parsedResult = self._parse_incoming(result)
		else:
			if self.hlapi.debug: print('Result is None, returning TIMEOUT')
			return 'TIMEOUT'
		resultParts = []
		for part in parsedResult:
			if len(part) > 1:
				# If the parsed data isn't an error code, try converting it to a frame
				try:
					frame = MessageFramer.UnpackFrame(part)
					resultParts.append(frame)
				except:
					if self.hlapi.debug: print('Could not parse frame from', self.ip, ':', part)
					pass
			elif len(part) == 1:
				if self.hlapi.debug: print('Response is error code:', repr(part))
				return None

		return resultParts

	# Writes a frame to the SPBUS
	# Input:	data:	Frame
	# Output:	True or False depening on how successful the write was
	def writeRaw(self, frame, elapsedTime=0):
		starttime = time.time()
		if not self.conn:
			return False
		# Turn the frame into a raw payload
		message = MessageFramer.PackFrame(frame)

		# Apply RC4 encryption and turn the raw payload into an SPBUS message
		encryptedData = self._datapre(message)

		try:
			ready_to_read, ready_to_write, in_error = select.select([], [self.sock], [], 0)

			if len(ready_to_write) == 0:
				if self.conn and elapsedTime < self.timeout:
					time.sleep(0.1)
					if self.hlapi.debug: print('Ready_to_write empty... Retry (writeRaw)')
					elapsedTime += time.time() - starttime
					return self.writeRaw(frame, elapsedTime=elapsedTime)
				if self.hlapi.debug: print('Write timeout', elapsedTime)
				return 'TIMEOUT'

			sent = 0
			while sent < len(encryptedData):
				sentbytes = self.sock.send(encryptedData[sent:])
				if sentbytes <= 0:
					if self.conn and elapsedTime < self.timeout:
						time.sleep(0.1)
						if self.hlapi.debug: print('Socket might be closed, reconnecting... no bytes sent (writeRaw)')
						elapsedTime += time.time() - starttime
						return self.writeRaw(frame, elapsedTime=elapsedTime)
					if self.hlapi.debug: print('Could not reconnect to socket, elapsed time:', elapsedTime)
					return 'TIMEOUT'
				sent += sentbytes
		except (socket.error, IOError, Exception) as e:
			if e.errno not in IPAPIProtocol.RECONNECT_ERRORS:
				if self.hlapi.debug: print(e, type(e))
				return 'TIMEOUT'
			if self.conn and elapsedTime < self.timeout:
				time.sleep(0.1)
				if self.hlapi.debug: print('Socket error:', e, 'Retry... (writeRaw)')
				elapsedTime += time.time() - starttime
				if e.errno in IPAPIProtocol.RECONNECT_ERRORS:
					self._openSocket()
				return self.writeRaw(frame, elapsedTime=elapsedTime)
			if self.hlapi.debug: print('Write timeout', elapsedTime, '(writeRaw)')
			return 'TIMEOUT'

		self.yieldTime = self.yieldSeconds
		return True

	# Helper method for initialising a frame
	def _composeFrame(self, action, start, length, unit=None, layer=0, data=None):
		f = Frame()
		if action == 'read':
			f.Fields = ReadRegisterFields
			f.setField(COMMAND, f.CMD_READ[layer])
		elif action == 'write':
			f.Fields = WriteRegisterFields
			f.setField(COMMAND, f.CMD_WRITE[layer])
			f.setField(DATA, data)

		if unit is not None:
			f.setField(UNITADDRESS, unit)

		f.setField(REGISTERSTART, start)
		f.setField(REGISTERLENGTH, length)
		return f

	# Composes a serialized data string for multiple registers ready to be attached to a frame
	# Input:	registers:	the registers associated with the given data
	#			data:		a list of (unserialized write) values for each register
	# Output:	A list length 2, the first element being the serialized string for layer 0,
	#			the second element is either '' or filled with serialized data for layer 1 depending
	#			on whether one or more of the registers makes use of the extended layer
	def _composeRegisters(self, registers, data):
		result = [b'', b'']
		# Iterate given registers
		for i in range(len(registers)):
			append = b''
			# Get register location and length
			location = registers[i].RegisterStart
			length = registers[i].RegisterLength

			# If the current register is not the last register
			if i+1 < len(registers):
				# Calculate the space (in register addresses) between this register and the next one
				delta = registers[i+1].RegisterStart - (location+length*registers[i].Repeats)
				# Append (invisible) zeroes to fill up gaps between registers,
				# this needs to be done to prevent accidental writes to the wrong registers
				append = append.ljust(delta, b'\x00')

			# Get the input data for this register
			# Could be a single value, could be a list
			value = data[registers[i].Mnemonic]
			if registers[i].Repeats == 1:
				# For a single-repeat register, just serialize the data and append it to result (layer 0)
				dataStr = self._serialize(value, registers[i])
				if dataStr is None:
					return None
				result[0] += dataStr + append
			else:
				# Multi-repeat register, iterate over the input values
				for j in range(len(value)):
					# If the register uses the extension layer (1), write the second half of the input list
					# to this layer and the first half to layer 0.
					# If the register doesn't use the extended layer, write all values to layer 0.
					if registers[i].Extension and j > (len(value)/2)-1:
						layer = 1
					else:
						layer = 0
					# Serialize the current value for the current register
					dataStr = self._serialize(value[j], registers[i])
					if dataStr is None:
						return None
					# Append the serialized data to the calculated layer
					result[layer] += dataStr

				# Fill up the gap between this register and the next for layer 0
				result[0] += append
				# Same thing for layer 1, only if this register is using the extended layer.
				if registers[i].Extension:
					result[1] += append

		return result

	# Does the exact opposite of _composeRegisters()
	# Turns the raw frame data of one or two layers into a dictionary of register values
	#
	# Input:	data:		a serialized frame data string
	#			registers:	the registers to which the input data belongs
	#			mergeBase:	None or the result from _parseRegisters() for layer 0,
	#						so that the results (layer 0 (previous) + layer 1 (current)) can be merged.
	# Output:	A dictionary of register mnemonics as keys and deserialized values
	#			(values can be single values or lists of values)
	def _parseRegisters(self, data, registers, mergeBase):
		result = {}
		offset = 0
		for register in registers:
			length = register.RegisterLength
			repeats = register.Repeats
			size = length*repeats

			# Extract the needed amount of bytes for the current register from the input data
			# starting at the right offset, increase the offset afterwards.
			registerData = data[offset:offset+size]
			offset += size

			if repeats > 1:
				# Multi-repeat register

				# Parse the data string into a list of values
				registerData = self._parseRepeats(registerData, length)

				# Deserialize all values
				for i in range(len(registerData)):
					registerData[i] = self._deserialize(register.Mnemonic, registerData[i])

				if mergeBase is not None:
					# We're currently parsing the second layer, the results from layer 0's parsing are
					# currently waiting in mergeBase
					if register.Extension:
						# Extended register
						registerData = mergeBase[register.Mnemonic] + registerData
					else:
						registerData = mergeBase[register.Mnemonic]

				# RegisterData is a list of values for the current register
			else:
				# Single value register
				if mergeBase is not None:
					# Second layer read, replace current value with previous layer's value
					# because a single-repeat register can't have an extended layer
					registerData = mergeBase[register.Mnemonic]
				else:
					# First layer read
					# Deserialize data
					registerData = self._deserialize(register.Mnemonic, registerData)

			# Put the (merged) result in our dictionary
			result[register.Mnemonic] = registerData

		return result

	# Chops a raw data string into pieces of the same length
	# ideal for parsing a string into register data (multiple repeats)
	def _parseRepeats(self, data, regLength):
		out = []
		while data:
			out.append(data[:regLength])
			data = data[regLength:]
		return out

	# Extracts the actual payload from a single SPBUS message
	# Input:	data:	SPBUS message
	# Output:	raw payload
	def _parse_payload(self, data):
		# Decrypt message and verify header
		# Data is string
		payload = self._crypt(data)
		# Payload is string
		if payload[:4] != self.key[:4]:
			return None

		# Verify checksum
		#checksum_calc = self._checksum(payload[:-4])
		checksum_calc = sum([ord(x) for x in payload[:-4]])
		# >I = unsigned int, big endian, int (4)
		checksum_wire = struct.unpack(">I", bytes([ord(x) for x in payload[-4:]]))[0]
		# if self.hlapi.debug: print(repr(checksum_calc)+" and "+repr(checksum_wire))
		if checksum_calc != checksum_wire:
			return None

		return bytes([ord(x) for x in payload[4:-4]])

	# Transforms incoming SPBUS message string into a list of parsed payloads
	# Input:	data:	SPBUS message string
	# Output:	List(raw payload)
	def _parse_incoming(self, data):
		parsed = []
		remaining = data
		payload_len = None

		gotPassedOnBytes = False

		if len(self.passOn) > 0:
			gotPassedOnBytes = True
			if self.hlapi.debug: print("-> Prepending", len(self.passOn), "unparsable bytes to input")
			remaining = self.passOn + remaining
			self.passOn = b''

		# SPBUS MESSAGE: 'SAPI' + LEN + crypt(KEY + DATA + CHECKSUM) = PAYLOAD
		# bytes:		   4	  2			(4		?		  4)

		# Iterate over the string until exhausted (if the remaining length is smaller than 6,
		# the message can't be valid as the 'SAPI' tag and length fields already use 6 bytes.
		while (len(remaining) >= 6):
			if remaining[:4] != b'SAPI':
				# Seek first SAPI tag, should always be in front
				index = remaining.find(b'SAPI')
				if index != -1:
					if self.hlapi.debug: print('-> Stripping', index, 'bytes')
					remaining = remaining[index:]
				else:
					# Entire string doesn't contain SAPI.
					if self.hlapi.debug: print('-> Detected', len(remaining), 'lost bytes. Poor guys.')
					remaining = b''
					break

			# remaining is now b'SAPI.......SAPI........(SAPI.......)'
			# >H = unsigned short, big endian, int (2)
			payload_len = struct.unpack('>H', remaining[4:6])[0]
			if payload_len < 8:
				# Payload length must be greater or equal than 8 in order to be valid
				if self.hlapi.debug: print('Invalid payload length')
				if index != -1:
					if self.hlapi.debug: print('-> Stripping', index, 'bytes')
					remaining = remaining[index:]
				else:
					# Entire string doesn't contain SAPI.
					if self.hlapi.debug: print('-> Detected', len(remaining), 'lost bytes. Poor guys.')
					remaining = b''
					break
			else:
				# Extract payload
				payload = remaining[6:(6+payload_len)]
				# Parse payload
				str_payload = "".join(str(chr(n)) for n in payload)
				parsed_payload = self._parse_payload(str_payload)

				if parsed_payload is not None:
					if gotPassedOnBytes:
						gotPassedOnBytes = False
						if self.hlapi.debug: print("Successfully reassembled payload from lost bytes!")
					# Append to result and update remaining
					parsed.append(parsed_payload)
					remaining = remaining[(6+payload_len):]
				else:
					# Couldn't parse payload
					# Find the next occurence of SAPI and use everything in front of it as a new payload instead of
					# using the given (fixed) payload length.
					nextSAPI = remaining[4:].find(b'SAPI')
					if nextSAPI != -1:
						nextSAPI += 4
					else:
						nextSAPI = len(remaining)
					possiblePayload = remaining[6:nextSAPI]
					str_payload = "".join(str(chr(n)) for n in possiblePayload)
					parsed_payload = self._parse_payload(str_payload)
					if parsed_payload is not None:
						# Success, add to result
						parsed.append(parsed_payload)
					else:
						# Pass on to the next iteration
						self.passOn += remaining[:nextSAPI]
						if self.hlapi.debug: print("-> Passing on", len(self.passOn), "unparsable bytes to next iteration")
					remaining = remaining[nextSAPI:]

		# Pass on any unparsable data
		self.passOn += remaining

		return parsed

	# Calculates checksum
	def _checksum(self, data):
		# data is string
		unpackstr = str(len(data.encode())) + 'B'
		return sum(struct.unpack(unpackstr, data.encode()))
		# return is int

	# Encrypts data using ARC4
	def _crypt(self, data):
		# data is string like '0000\x02\x01\x00\x00\x01\x00f\x00\x02\x00\x19\x89\x03\x00\x00\x01Ñ'
		self._cryptor = Arc4(self.key)
		return self._cryptor.translate(data)
		# return is string

	# Converts a raw payload into an encrypted SPBUS message
	def _datapre(self, data):
		# SPBUS MESSAGE: 'SAPI' + LEN + crypt(KEY + DATA + CHECKSUM) = PAYLOAD
		# bytes:		   4	  2			(4		?		  4)

		# input data is bytes

		key_data = self.key[:4].encode() + data
		#chksum = struct.pack(">I", self._checksum("".join(str(chr(n)) for n in key_data)))
		chksum = struct.pack(">I", sum([int(x) for x in key_data]))
		payload = key_data + chksum

		# if self.hlapi.debug: print("Payload: "+str(payload))
		# payload = b'0000\x02\x01\x00\x00\x01\x00f\x00\x02\x00\x19\x89\x03\x00\x00\x01\xd1'

		str_payload = "".join(str(chr(n)) for n in payload)

		# str_payload = '0000\x02\x01\x00\x00\x01\x00f\x00\x02\x00\x19\x89\x03\x00\x00\x01Ñ'
		cryptPayload = self._crypt(str_payload)

		if self._parse_payload(cryptPayload) != data:
			if self.hlapi.debug: print('Payload encryption reverse verification failed.')
			exit()

		# "binary" -> b"binary": bytes([ord(x) for x in y])
		# b"binary" -> "binary": "".join(str(chr(x)) for x in y)
		# b"binary" -> hex list: [hex(ord(x)) for x in k]
		# b"string" -> hex bytes: bytes([int(hex(x)[2:]) for x in y])

		cryptPayload = bytes([ord(x) for x in cryptPayload])
		#			TAG				LENGTH						enc(KEY + DATA + CHECKSUM)
		retData = b'SAPI' + struct.pack(">H", len(cryptPayload)) + cryptPayload
		# if self.hlapi.debug: print("Sending: "+str(retData))
		return retData

	# Serializes a value depening on the type of register the value belongs to
	# A serialized value can be attached to a frame's DATA field
	def _serialize(self, value, register):
		regType = register.Type
		try:
			if regType == ASCII:
				return value.ljust(register.RegisterLength, '\0').encode()
			elif regType == IPV4:
				return struct.pack('<L', struct.unpack("!I", socket.inet_aton(value))[0])
			elif regType == FD:
				if value > 327.67:
					value *= 10.0
					value += 32767.0
				else:
					value *= 100.0
				value += 0.5
				return struct.pack('<H', int(value))
			elif regType == INT:
				if register.RegisterLength == 1:
					return struct.pack('B', value)
				elif register.RegisterLength == 2:
					return struct.pack('<H', value)
				elif register.RegisterLength == 4:
					return struct.pack('<L', value)
				elif register.RegisterLength == 6:
					# MAC address
					result = b''
					parts = value.split(':')
					for part in parts:
						result += struct.pack('<B', int(part, 16))
					return result
		except Exception as e:
			if self.hlapi.debug: print('Datatype error '+str(e)+' ('+str(register.Mnemonic)+'):', value)
			return None

	# Deserializes a value depending on the type of register the value belongs to
	# A deserialized value should be human readable
	def _deserialize(self, reg, data):
		reg = RegisterHelper.registerLookup(reg)
		result = None
		# if self.hlapi.debug: print("DATA "+str(data))

		if data is not None:
			try:
				if reg.Type == ASCII:
					size = reg.RegisterLength
					#return self._removeControlChars(struct.unpack('{0}s'.format(size), data)[0])
					# b'test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
					# -> test
					try:
						i = data.find(b'\0')
						if i != -1:
							data = data[:i]

						result = "".join(str(chr(x)) for x in data)
						result = HLAPIHelper.removeControlChars(result)
					except Exception as e:
						if self.hlapi.debug: print("IPAPIProtocol STR decode error:", e)
						result = 'DECODE_ERR'

				elif reg.Type == IPV4:
					result = socket.inet_ntoa(struct.pack("!I", struct.unpack('<L', data)[0]))
				elif reg.Type == FD:
					fdRaw = struct.unpack('<H', data)[0]
					if fdRaw > 32767:
						result = (fdRaw-32767) / 10.0
					else:
						result = fdRaw / 100.0
				elif reg.Type == INT:
					if reg.RegisterLength == 1:
						result = struct.unpack('B', data)[0]
					elif reg.RegisterLength == 2:
						result = struct.unpack('<H', data)[0]
					elif reg.RegisterLength == 3:
						val = data + b'\x00'
						result = struct.unpack('<L', val)[0]
					elif reg.RegisterLength == 4:
						result = struct.unpack('<L', data)[0]
					elif reg.RegisterLength == 6:
						# To lower because the WEBAPI returns a lowercase MAC address
						result = ':'.join('{0:02x}'.format(i, 'x') for i in struct.unpack('BBBBBB', data)).lower()
			except Exception as e:
				if self.hlapi.debug: print("Parsing of register", reg.Mnemonic, "failed! (IPAPIProtocol)", "Data: "+str(data), "Error:", e)

			if result is not None:
				return result
			else:
				return None
