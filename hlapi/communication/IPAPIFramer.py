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
import struct

# Library imports
from .. library.crcmod import *

calculateCrc = mkCrcFun(0x11021, rev=False, initCrc=0xFFFF)

# Collection of frame fields
#
class							 FieldEnum	: pass
class STARTBYTE					(FieldEnum) : pass
class COMMAND					(FieldEnum) : pass
class HARDWAREID				(FieldEnum) : pass
class STATUS					(FieldEnum) : pass
class UNITADDRESS				(FieldEnum) : pass
class TRANSACTIONID				(FieldEnum) : pass
class REGISTERSTART				(FieldEnum) : pass
class REGISTERLENGTH			(FieldEnum) : pass
class RESERVED					(FieldEnum) : pass
class DATA						(FieldEnum) : pass
class CRC						(FieldEnum) : pass
class ENDBYTE					(FieldEnum) : pass

# Standard field structures depending on command
#
ReadRegisterFields = [ UNITADDRESS, TRANSACTIONID, REGISTERSTART, REGISTERLENGTH ]
ReadRegisterAckFields = [ UNITADDRESS, TRANSACTIONID, REGISTERSTART, REGISTERLENGTH, DATA ]
ReadRegisterNakFields = [ UNITADDRESS, TRANSACTIONID, RESERVED ]
WriteRegisterFields = [ UNITADDRESS, TRANSACTIONID, REGISTERSTART, REGISTERLENGTH, DATA ]
WriteRegisterAckFields = [ UNITADDRESS, TRANSACTIONID ]
WriteRegisterNakFields = [ UNITADDRESS, TRANSACTIONID, RESERVED ]
SetAddressFields = [ HARDWAREID, UNITADDRESS ]
SetAddressAckFields = [ HARDWAREID, UNITADDRESS ]
SetAddressNakFields = [ HARDWAREID, UNITADDRESS, RESERVED ]
DisplaysOnFields = []
DisplaysOffFields = []
ScanFields = []
ScanAckFields = [ UNITADDRESS, HARDWAREID ]
StatusFields = []
StatusAckFields = [ UNITADDRESS, STATUS ]
BroadcastWriteRegisterFields = [ REGISTERSTART, REGISTERLENGTH, DATA ]

# Single frame field
#
class Field(object):
	size = None
	value = None
	fieldType = None

	def __init__(self, size, value, fieldType):
		self.size = size
		self.value = value
		self.fieldType = fieldType

	def __str__(self):
		if self.value is None:
			return ""
		else:
			return str(self.value)

# Frame class, contains frame Fields
# each valid SPBUS payload can be converted to a frame (using MessageFramer)
#
class Frame(object):
	# Constant control characters
	STX = [ 0x02 ] # start of text (end of header)
	ETX = [ 0x03 ] # end of text (start of footer)
	ACK = [ 0x06 ] # acknowledgement, status ok
	NAK = [ 0x0F, 0x15 ] # error

	# Commands
	CMD_READ = [ 1, 2 ]
	CMD_WRITE = [ 16, 17 ]
	CMD_SETADDRESS = [ 32 ]
	CMD_BRSCAN = [ 144 ]
	CMD_BRSTATUS = [ 145 ]
	CMD_BRWRITE = [ 160, 161 ]
	CMD_DISPLAYON = [ 128 ]
	CMD_DISPLAYOFF = [ 129 ]

	# Header and footer fields
	FieldsBefore = [ STARTBYTE, COMMAND ]
	FieldsAfter = [ CRC, ENDBYTE ]

	def __init__(self):
		self.FRAME = {}
		self.Fields = []

		self.FRAME[STARTBYTE]		 = Field(1, self.STX[0], STARTBYTE)
		self.FRAME[COMMAND]			 = Field(1, None, COMMAND)
		self.FRAME[HARDWAREID]		 = Field(6, None, HARDWAREID)
		self.FRAME[RESERVED]		 = Field(1, None, RESERVED)
		self.FRAME[STATUS]			 = Field(6, None, STATUS)
		self.FRAME[UNITADDRESS]		 = Field(2, None, UNITADDRESS)
		self.FRAME[TRANSACTIONID]	 = Field(2, None, TRANSACTIONID)
		self.FRAME[REGISTERSTART]	 = Field(2, None, REGISTERSTART)
		self.FRAME[REGISTERLENGTH]	 = Field(2, None, REGISTERLENGTH)
		self.FRAME[DATA]			 = Field(0, None, DATA)
		self.FRAME[CRC]				 = Field(2, None, CRC)
		self.FRAME[ENDBYTE]			 = Field(1, self.ETX[0], ENDBYTE)

	def __str__(self):
		return "frame: " + str(self.FRAME[STARTBYTE]) + " CMD: " + str(self.FRAME[COMMAND]) + " HWID: " + str(self.FRAME[HARDWAREID]) + " RES: " + str(self.FRAME[RESERVED]) + " STATUS: " + str(self.FRAME[STATUS]) + " UNITADDR: " + str(self.FRAME[UNITADDRESS]) + " TID: " + str(self.FRAME[TRANSACTIONID]) + " REGSTART: " + str(self.FRAME[REGISTERSTART]) + " REGLNG: " + str(self.FRAME[REGISTERLENGTH]) +	" DATA:" + str(self.FRAME[DATA]) + " CRC: " + str(self.FRAME[CRC]) + " END: " + str(self.FRAME[ENDBYTE])

	def findField(self, FieldType):
		return self.FRAME[FieldType]

	def setField(self, FieldType, value):
		f = self.findField(FieldType)
		if f is not None:
			f.value = value

# MessageFramer
# Handles conversion between frames and SPBUS commands
#
class MessageFramer(object):
	_transactionID = 1
	# Static method used to convert from Frame structure to an spbus payload.
	#
	# Input:	'frame', Frame structure used that denotes the message frame
	#			separated by field.
	# Output:	'message', message frame command as expected on spbus
	#			communication level.
	@classmethod
	def PackFrame(cls, frame):
		message = b""
		transactionField = frame.findField(TRANSACTIONID)
		if transactionField is not None:
			transactionField.value = cls._transactionID
			cls._transactionID += 1

		for f in frame.FieldsBefore:
			field = frame.findField(f)
			message += cls._stringify(field)

		for f in frame.Fields:
			field = frame.findField(f)
			message += cls._stringify(field)

		field = frame.findField(CRC)
		message += cls._calculateCrc(message)

		field = frame.findField(ENDBYTE)
		message += cls._stringify(field)
		return message

	# Returns the required fields for a certain command
	#
	@classmethod
	def findFieldFormat(cls, startbyte, command):
		ret = None
		if startbyte == Frame.STX[0]:
			return ret
		elif startbyte == Frame.ACK[0]:
			if command == Frame.CMD_READ[0] or command == Frame.CMD_READ[1]:
				ret = ReadRegisterAckFields
			elif command == Frame.CMD_WRITE[0] or command == Frame.CMD_WRITE[1]:
				ret = WriteRegisterAckFields
			elif command == Frame.CMD_SETADDRESS[0]:
				ret = SetAddressAckFields
			elif command == Frame.CMD_BRSCAN[0]:
				ret = ScanAckFields
			elif command == Frame.CMD_BRSTATUS[0]:
				ret = StatusAckFields
		elif startbyte == Frame.NAK[0] or startbyte == Frame.NAK[1]:
			if command == Frame.CMD_READ[0] or command == Frame.CMD_READ[1]:
				ret = ReadRegisterNakFields
			elif command == Frame.CMD_WRITE[0] or command == Frame.CMD_WRITE[1]:
				ret = WriteRegisterNakFields
			elif command == Frame.CMD_SETADDRESS[0]:
				ret = SetAddressNakFields
		return ret

	# Static method used to convert from an spbus payload to a Frame structure.
	# Input:	'message', the reply message as received from spbus
	#			communication.
	# Output:	'frame', a Frame structure with each field filled in accordance
	#			with the reply data
	@classmethod
	def UnpackFrame(cls, message):
		frame = Frame()

		offset = 0
		for fieldType in frame.FieldsBefore:
			f = frame.findField(fieldType)
			if f.size is 1:
				value = struct.unpack_from("<B", message, offset)[0]
				offset += f.size
				f.value = value
			else:
				#panic
				pass

		startField = frame.findField(STARTBYTE)
		commandField = frame.findField(COMMAND)

		frame.Fields = cls.findFieldFormat(startField.value, commandField.value)

		for fieldType in frame.Fields:
			f = frame.findField(fieldType)
			if f.size is 1:
				value = struct.unpack_from("<B", message, offset)[0] # 1x unsigned char integer 1
			elif f.size is 2:
				value = struct.unpack_from("<H", message, offset)[0] # 1x unsigned short integer 2
			elif f.size is 6 and f.fieldType is STATUS:
				value = struct.unpack_from("BBBBBB", message, offset)[0] # 6x unsigned char integer 1
			elif f.size is 6 and f.fieldType is HARDWAREID:
				value = "-".join(str(x) for x in struct.unpack_from("<HHH", message, offset)) # 3x unsigned short integer 2
			elif f.size is 0:
				ft = frame.findField(REGISTERLENGTH)
				value = struct.unpack_from(str(ft.value) + "s", message, offset)[0]
				offset += ft.value
			offset += f.size
			f.value = value
		for fieldType in frame.FieldsAfter:
			f = frame.findField(fieldType)
			if f.size is 1:
				value = struct.unpack_from("<B", message, offset)[0]
			elif f.size is 2:
				value = struct.unpack_from("<H", message, offset)[0]
			else:
				#panic
				pass
			offset += f.size
			f.value = value

		return frame

	# 'Private' method to help convert each Frame struct field into its string
	# equivalent (keeping in mind the endianness).
	# Input:	'curField', denotes the current Frame field we're processing
	# Output:	'ret', return string with the right format for said field
	@classmethod
	def _stringify(cls, curField):
		ret = b""
		if curField.value is not None:
			if curField.size is 1:
				ret = struct.pack("<B", curField.value)
			elif curField.size is 2:
				ret = struct.pack("<H", curField.value)
			elif curField.size is 6:
				if curField.fieldType == HARDWAREID:
					splitted = curField.value.split('-')
					ret = struct.pack("<HHH", int(splitted[0]), int(splitted[1]), int(splitted[2]))
				else:
					ret = struct.pack("<HHH", curField.value[0], curField.value[1], curField.value[2])
			elif curField.size is 0:
				ret = curField.value

		return ret

	# Calculate crc checksum for a given message
	@classmethod
	def _calculateCrc(self, message):
		crc = calculateCrc(message)
		# print("RAW CRC: "+str(crc))
		return struct.pack('<H', crc)
