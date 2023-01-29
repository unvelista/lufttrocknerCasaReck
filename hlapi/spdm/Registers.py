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

# SPDM datatypes
class INT: pass
class ASCII: pass
class FD: pass
class IPV4: pass
class IPV6: pass

# Register instance
class Register(object):
	Mnemonic = None
	RegisterStart = None
	RegisterLength = None
	Repeats = None
	Extension = None
	Type = None
	Group = None
	Added = None
	Read = None
	Write = None
	WriteAccess = None
	RebootRequired = None
	Name = None
	Description = None

	# mnemonic,	loc,	len,	rep,	ext,	type,	group,	added,	read,	write,	access,	name,	description
	def __init__(self, mnemonic, registerStart, registerLength, repeats, extension, type, group, added, read, write, access, reboot, name, description):
		self.Mnemonic = mnemonic
		self.RegisterStart = registerStart
		self.RegisterLength = registerLength
		self.Repeats = repeats
		self.Extension = extension
		self.Type = type
		self.Group = group
		self.Added = added
		self.Read = read
		self.Write = write
		self.WriteAccess = access
		self.RebootRequired = reboot
		self.Name = name
		self.Description = description

# SPDM 2.51
#
# 			mnemonic,	loc,	len,rep,ext,	type,	group,				added,	read,			write,				access,		reboot,	name,							description
#
Registers = [
	Register("idspdm",	100,	2,	1,	False,	INT,	"identification",	0,		"ALL",			"-",				"-",		False,	"SPDMVersion",					"Data model version (2.40 current)"),
	Register("idfwvs",	102,	2,	1,	False,	INT,	"identification",	0,		"ALL",			"-",				"-",		False,	"firmwareVersion",				"Firmware version number (2.40 current)"),
	Register("idonbr",	104,	16,	1,	False,	ASCII,	"identification",	0,		"ALL",			"IPAPI,WEBAPI",		"super",	False,	"salesOrderNumber",				"SP sales order number."),
	Register("idpart",	120,	16,	1,	False,	ASCII,	"identification",	0,		"ALL",			"IPAPI,WEBAPI",		"super",	False,	"productId",					"SP product id."),
	Register("idsnbr",	136,	16,	1,	False,	ASCII,	"identification",	0,		"ALL",			"IPAPI,WEBAPI",		"super",	False,	"serialNumber",					"SP serial number."),
	Register("idchip",	152,	2,	3,	False,	INT,	"identification",	0,		"ALL",			"-",				"-",		False,	"hardwareAddress",				"Hardware serial number; cannot be changed. Can be used as backup unit address. Formatted as a 3-tuple of unsigned 16 bit integers separated by dashes: \"int - int - int\""),
	Register("idaddr",	158,	2,	1,	False,	INT,	"identification",	0,		"ALL",			"ALL",				"admin",	False,	"unitAddress",					"User defined address; this will be used for addressing the unit."),
	Register("idfwbd",	160,	12,	1,	False,	ASCII,	"identification",	124,	"ALL",			"-",				"-",		False,	"buildNumber",					"Firmware build number; date of last release."),
	Register("idmaca",	172,	6,	1,	False,	ASCII,	"identification",	126,	"ALL",			"-",				"-",		False,	"macAddress",					"MAC address as 6-tuple of bytes."),
	Register("idspdt",	178,	1,	1,	False,	INT,	"identification",	130,	"ALL",			"-",				"-",		False,	"deviceType",					"Device category: 0 for PDU, 1 for DPM, 2 for PDUG3, 3 for DPM27/e"),
	Register("cfnrph",	200,	1,	1,	False,	INT,	"configuration",	0,		"ALL",			"IPAPI,WEBAPI",		"super",	False,	"nrPhases",						"Either zero, one or three for no input metering, single or three phase system"),
	Register("cfnrno",	201,	1,	1,	False,	INT,	"configuration",	0,		"ALL",			"IPAPI,WEBAPI",		"super",	False,	"nrOutletsTotal",				"Total number of outlets, even hardwired ones without a switch/measure modules."),
	Register("cfnrso",	202,	1,	1,	False,	INT,	"configuration",	0,		"ALL",			"IPAPI,WEBAPI",		"super",	False,	"nrSwitchedOutl",				"Number of switched outlets. If numbering of outlets used is non-contiguous: the highest outlet number is assumed as amount of switched outlets."),
	Register("cfnrmo",	203,	1,	1,	False,	INT,	"configuration",	0,		"ALL",			"IPAPI,WEBAPI",		"super",	False,	"nrOutletsMeasurement",			"Number of measured outlets. If numbering of outlets used is non-contiguous: the highest outlet number is assumed as amount of measured outlets."),
	Register("cfamps",	204,	1,	1,	False,	INT,	"configuration",	0,		"ALL",			"IPAPI,WEBAPI",		"super",	False,	"maximumLoad",					"Maximum rated load of device per phase, usually either 16, 32 or 64A."),
	Register("cfnres",	206,	1,	1,	False,	INT,	"configuration",	0,		"ALL",			"-",				"-",		False,	"nrSensors",					"Returns the number of detected environmental sensors on the sensor port."),
	Register("cfusbm",	220,	1,	1,	False,	INT,	"configuration",	251,	"ALL",			"IPAPI,WEBAPI",		"super",	False,	"USB",							"0 = USB disabled, 1 = Only firmware update"),
	Register("cfsltp",	297,	1,	1,	False,	INT,	"configuration",	244,	"IPAPI",		"IPAPI,WEBAPI",		"super",	False,	"ConfigSlaveType",				"Set the slave type: 0 = slave9, 1 = slave6"),
	Register("ssstat",	300,	1,	1,	False,	INT,	"system_status",	0,		"ALL",			"-",				"-",		False,	"deviceStatusCode",				"Returns internal device status. 0 = OK, 1 = alert flagged, 16 = watchdog timer caused reset, 32 = brownout detected, 128 = slave module was reset"),
	Register("ssttri",	301,	1,	1,	False,	INT,	"system_status",	0,		"ALL",			"-",				"-",		False,	"temperatureAlert",				"Alert status on whether temperature exceeded configured threshold and on which sensor it exceeded. 0 = no alert, 1 = internal unit temperature, 2 = external sensor"),
	Register("ssitri",	302,	1,	1,	False,	INT,	"system_status",	0,		"ALL",			"-",				"-",		False,	"inputCurrentAlert",			"Alert status on whether input current load exceeded threshold and which input phase it affected. 0 = no alert 1-3 input phase"),
	Register("ssotri",	303,	1,	1,	False,	INT,	"system_status",	0,		"ALL",			"-",				"-",		False,	"outputCurrentAlert",			"Alert status on whether output current exceeded threshold. 0 = no alert, 1-48 = outlet number"),
	Register("ssvtri",	304,	1,	1,	False,	INT,	"system_status",	0,		"ALL",			"-",				"-",		False,	"inputVoltageAlert",			"Alert status on whether a voltage drop occurred on the input. 0 = no alert, 1-3 input phase"),
	Register("ssftri",	305,	1,	1,	False,	INT,	"system_status",	0,		"ALL",			"-",				"-",		False,	"oCurrentDropAlert",			"Alert status on whether a current drop occured (to nearly 0A) on one of the outlets, indicating a possible blown fuse. 0 = no alert, 1-48 = outlet number"),
	Register("ssicda",	306,	1,	1,	False,	INT,	"system_status",	0,		"ALL",			"-",				"-",		False,	"iCurrentDropAlert",			"Alert status on whether current a current drop occured (to nearly 0A) on one of the input phases. 0 = no alert 1-3 = input phase"),
	Register("sssnsa",	307,	1,	1,	False,	INT,	"system_status",	126,	"ALL",			"-",				"-",		False,	"sensorChangeAlert",			"Alert status on whether the sensor type changed. 0 = no alert, 1 = sensor type changed"),
	Register("ssovda",	308,	1,	1,	False,	INT,	"system_status",	240,	"ALL",			"-",				"-",		False,	"outletVoltageDropAlert",		"Alert status on whether a voltage drop occurred on one of the outlets, indicating a possible blown fuse or otherwise failing outlet. 0 = no alert, 1-48 = outlet number where the drop was first detected (not necessarily the first to fail)"),
	Register("rsboot",	400,	1,	1,	False,	INT,	"reset",			0,		"-",			"ALL",				"user",		False,	"rebootDevice",					"Writing '1' to this register will invoke a warm restart/reset of the device. Note that this will have no effect on outlet status!"),
	Register("rsalrt",	401,	1,	1,	False,	INT,	"reset",			0,		"-",			"ALL",				"user",		False,	"resetAlerts",					"Writing any non-zero integer to this register will reset all alerts."),
	Register("rsimks",	402,	1,	1,	False,	INT,	"reset",			0,		"-",			"IPAPI",			"power",	False,	"zeroInputKWhSubtotal",			"Writing any non-zero integer	to this register will reset the input kWh subtotal counters to zero."),
	Register("rsomks",	403,	1,	27,	True,	INT,	"reset",			0,		"-",			"IPAPI",			"power",	False,	"zeroOutKWhSubtotal",			"Writing any non-zero integer to a channel of this register will reset the corresponding outlet's kWh subtotal counter to zero."),
	Register("rspval",	430,	1,	1,	False,	INT,	"reset",			0,		"-",			"ALL",				"user",		False,	"resetPeakValues",				"Writing '1' to this register will reset all peak values to zero for both input/output metering, voltage drops, current and temperatures peaks."),
	Register("rsipks",	431,	1,	3,	False,	INT,	"reset",			130,	"-",			"IPAPI",			"power",	False,	"zeroSingleInputKWhSubtotal",	"Writing any non-zero integer to one of the 3 channels will reset the kWh subtotal counter to zero for the responding phase input."),
	Register("stdvnm",	1000,	16,	1,	False,	ASCII,	"settings",			0,		"ALL",			"ALL",				"admin",	False,	"deviceName",					"User configurable device name or identifier."),
	Register("stdvlc",	1016,	16,	1,	False,	ASCII,	"settings",			0,		"ALL",			"ALL",				"admin",	False,	"deviceLocation",				"User configurable device location identifier."),
	Register("stuser",	1032,	20,	1,	False,	ASCII,	"settings",			0,		"ALL",			"ALL",				"admin",	False,	"vanityTag",					"String to be displayed as vanity text on the display."),
	Register("stpkdr",	1052,	2,	1,	False,	INT,	"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"peakDuration",					"Denotes the duration of a peak before an alert will be triggered. Put differently, if a current peak lasts at least [stpkdr] milliseconds, then an alert is raised. Maximum time is roughly a minute."),
	Register("strsal",	1054,	1,	1,	False,	INT,	"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"localAlertReset",				"Setting this register to '1' will allow a physical alert status reset by pressing both device buttons simultaneously. Without this set pressing both buttons at the same time will default the display to the 'LOAD' tab."),
	Register("stextn",	1055,	1,	1,	False,	INT,	"settings",			240,	"ALL",			"ALL",				"admin",	False,	"extendedNames",				"Setting this register to '1' will enable the use of the 18 character registers for input, outlet and sensor names to display the name on the LCD, web interface and SNMP."),
	Register("stfodl",	1056,	2,	1,	False,	INT,	"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"fixedOutletDelay",				"Minimal delay between relay switch requests in milliseconds. Minimal delay is 100 ms and will therefore always be respected!"),
	Register("stpsav",	1058,	1,	1,	False,	INT,	"settings",			0,		"ALL",			"IPAPI",			"user",		False,	"powerSaverMode",				"Delay, in seconds, until backlight should deactivate; 0 keeps display always on. Note that keeping the backlight on for extended periods may decrease luminosity. Setting this to other values than 10, 60, 120 or 240 is incompatible with the gateway!"),
	Register("stopom",	1059,	1,	1,	False,	INT,	"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"outletPowerupMode",			"Behaviour of outlet on power-up. 0 = off, 1 = same state as at power down use default switch delay. 2 = same state, but delayed by individual delay timer"),
	Register("stmaxt",	1060,	1,	1,	False,	INT,	"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"maximumTemperature",			"A temperature alert should be raised whenever the temperature is above this register's value. A value of zero means this setting is disabled. Applies to internal temperature unless an external sensor is connected. Value is in degrees celcius."),
	Register("stdiso",	1061,	1,	1,	False,	INT,	"settings",			0,		"ALL",			"ALL",			"user",		False,	"displayOrientation",			"Orientation of the display's user interface. 0 = no display, 1 = vertical, default orientation, 2 = vertical, upside down, 3 = horizontal, 90 degrees clockwise from default orientation. 4 = horizontal, 90 degrees counter-clockwise from default orientation"),
	Register("stimcm",	1062,	2,	3,	False,	FD,		"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"maxInletAmps",					"Maximum current per input phase. If an input current value exceeds this value and lasts at least [stpkdr] milliseconds, then an alert will be triggered."),
	Register("stomcm",	1068,	2,	27,	True,	FD,		"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"maxOutletAmps",				"Maximum current per outlet. If an outlet current value exceeds this value and lasts at least [stpkdr] milliseconds, then an alert will be triggered."),
	Register("stomct",	1122,	1,	27,	True,	INT,	"settings",			0,		"ALL",			"-",				"power",	False,	"outputCTratio",				"The multiplier to use in case /5 current transformers are used. Defaults to 1."),
	Register("stimct",	1149,	1,	3,	False,	INT,	"settings",			0,		"ALL",			"-",				"power",	False,	"inputCTratio",					"The multiplier to use in case /5 current transformers are used. Defaults to 1."),
	Register("stinnm",	1152,	8,	3,	False,	ASCII,	"settings",			0,		"ALL",			"ALL",				"admin",	False,	"inputName",					"User configurable naming of the inputs or phases."),
	Register("stolnm",	1176,	8,	27,	True,	ASCII,	"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"outletName",					"User configurable naming of individual outlets."),
	Register("stiodl",	1392,	2,	27,	True,	INT,	"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"indivOutletDelay",				"Delay before an individual outlet's relay switches on at power-up, in seconds."),
	Register("stcddt",	1446,	1,	1,	False,	INT,	"settings",			0,		"ALL",			"IPAPI",			"power",	False,	"currentDropDetection",			"Enables the current drop detection function. 0 = always off (default), 1 = input(s) only, 2 = output(s) only, 3 = both inputs and outputs"),
	Register("stsnsa",	1447,	1,	1,	False,	INT,	"settings",			126,	"ALL",			"IPAPI",			"power",	False,	"sensorChangeAlertMode",		"Enables the sensor channel change detection. 0 = off (default), 1 = on"),
	Register("stunlo",	1448,	1,	1,	False,	INT,	"settings",			132,	"ALL",			"IPAPI",			"user",		False,	"outletUnlock",					"Overrides the timeout of [swounl]. If this is set to 1 then the timeout will be ignored, otherwise the timeout will be taken into account."),
	Register("strebt",	1449,	1,	27,	True,	INT,	"settings",			132,	"ALL",			"IPAPI",			"user",		False,	"outletPowerCycle",				"Individual power cycle timer. This is the amount, in seconds, for each outlet (denoted by the channel) to wait until the relay should be switched on again."),
	Register("starsa",	1476,	2,	1,	False,	INT,	"settings",			240,	"ALL",			"IPAPI",			"power",	False,	"autoResetAlerts",				"Set to '0' to disable automatic resetting of alerts. Any other value (up to 65535) enables the automatic resetting of alerts. The configured number is the number of seconds to wait before resetting the alerts. The timer starts after an alert condition disappears. If in the mean time a new alert occurs, the timer will restart counting."),
	Register("swocst",	2000,	1,	27,	True,	INT,	"switched_outlets",	0,		"ALL",			"IPAPI",			"user",		False,	"currentState",					"The state of the outlet relay(s). Note that reading a '1' does not necessarily mean it's enabled at that very moment but could also mean that the outlet's scheduled to be enabled. Writing is only effective after setting [swounl], or [stunlo]."),
	Register("swosch",	2027,	1,	27,	True,	INT,	"switched_outlets",	0,		"ALL",			"-",				"-",		False,	"scheduled",					"A '1' indicates pending activity. Together with [swocst], this can denote the actual current state of the outlet relay(s) and whether it's planned to be enabled or disabled."),
	Register("sworeb",	2054,	1,	27,	True,	INT,	"switched_outlets",	126,	"-",			"IPAPI",			"user",		False,	"powerCycle",					"Writing '1' will cause the outlet to power cycle. Writing only effective if either [swounl] or [stunlo], and [swocst]'s value is set ([swounl] OR [stunlo]) AND [swocst]."),
	Register("swounl",	2081,	1,	27,	True,	INT,	"switched_outlets",	0,		"-",			"IPAPI",			"user",		False,	"unlock",						"Writing '1' to this register will release the safety for this outlet for a couple seconds. Switching and rebooting are temporarily enabled."),
	Register("imkwht",	3000,	3,	3,	False,	INT,	"input_measures",	0,		"ALL",			"-",				"-",		False,	"inputkWhTotal",				"Either the only phase in a single phase measurement; or one of the three phases in a multiphase measurement. This value is not resetable."),
	Register("imkwhs",	3009,	3,	3,	False,	INT,	"input_measures",	0,		"ALL",			"-",				"-",		False,	"inputkWhSubtotal",				"kWh subtotal register of the only phase in a single phase measurement; or one of three phases in a multiphase measurement. Reset to zero with [rsimks]."),
	Register("impfac",	3018,	2,	3,	False,	FD,		"input_measures",	0,		"ALL",			"-",				"-",		False,	"inputPowerFactor",				"The effective power factor in percent.(not available in Delta wiring mode)"),
	Register("imcrac",	3024,	2,	3,	False,	FD,		"input_measures",	0,		"ALL",			"-",				"-",		False,	"inputActualCurrent",			"Actual apparent, RMS current."),
	Register("imcrpk",	3030,	2,	3,	False,	FD,		"input_measures",	0,		"ALL",			"-",				"-",		False,	"inputPeakCurrent",				"Peak apparent, RMS current; highest value since last reset of the peaks."),
	Register("imvoac",	3036,	2,	3,	False,	FD,		"input_measures",	0,		"ALL",			"-",				"-",		False,	"inputActualVoltage",			"The actual voltage."),
	Register("imvodp",	3042,	2,	3,	False,	FD,		"input_measures",	0,		"ALL",			"-",				"-",		False,	"inputMinVoltage",				"RMS voltage dip; lowest value since reset of dips."),
	Register("imwkhf",	3048,	4,	3,	False,	INT,	"input_measures",	0,		"ALL",			"-",				"-",		False,	"inputWhSubtotal fraction",		"Fraction of kWh subtotal register, in microwatthour resolution, of the only phase in a single phase measurement; or one of three phases in a multiphase measurement. Reset to zero with [rsimks]."),
	Register("imname",	3060,	18,	3,	False,	ASCII,	"input_measures",	240,	"ALL",			"ALL",				"admin",	False,	"extendedInputName",			"User configurable naming of the inputs or phases."),
	Register("omkwht",	4000,	3,	27,	True,	INT,	"output_measures",	0,		"ALL",			"-",				"-",		False,	"outputkWhTotal",				"Total kWh of selected output. This value is not resetable."),
	Register("omkwhs",	4081,	3,	27,	True,	INT,	"output_measures",	0,		"ALL",			"-",				"-",		False,	"outputkWhSubtotal",			"kWh subtotal register of selected output. Reset to zero with [rsomks]."),
	Register("ompfac",	4162,	2,	27,	True,	FD,		"output_measures",	0,		"ALL",			"-",				"-",		False,	"outputPowerFactor",			"Power factor of output. (not available in Delta wiring mode)"),
	Register("omcrac",	4216,	2,	27,	True,	FD,		"output_measures",	0,		"ALL",			"-",				"-",		False,	"outputActualCurrent",			"Actual apparent, RMS current."),
	Register("omcrpk",	4270,	2,	27,	True,	FD,		"output_measures",	0,		"ALL",			"-",				"-",		False,	"outputPeakCurrent",			"Peak apparent, RMS current; highest value since last reset of peaks."),
	Register("omvoac",	4324,	2,	27,	True,	FD,		"output_measures",	0,		"ALL",			"-",				"-",		False,	"outputActualVoltage",			"Actual voltage on output. Note that these may differ with each other and input metering. This difference may amount to 2%."),
	Register("omuwhs",	4378,	4,	1,	False,	INT,	"output_measures",	0,		"ALL",			"-",				"-",		False,	"outletsMicroWhSubtotal",		"Fraction of sum of SUBWATTHR registers of all outlets in microwatthour units"),
	Register("pditem",	5000,	2,	1,	False,	FD,		"pdu_measures",		0,		"ALL",			"-",				"-",		False,	"pduIntTemperature",			"Actual internal device temperature in degrees celcius."),
	Register("pdetem",	5002,	2,	1,	False,	FD,		"pdu_measures",		0,		"ALL",			"-",				"-",		False,	"pduExtTemperature",			"Actual external device temperature in degrees celcius (read from a plugged-in sensor)."),
	Register("pdinpk",	5004,	2,	1,	False,	FD,		"pdu_measures",		0,		"ALL",			"-",				"-",		False,	"pduIntPeak temp",				"Peak internal device temperature in degrees celcius since last peak reset."),
	Register("pdexpk",	5006,	2,	1,	False,	FD,		"pdu_measures",		0,		"ALL",			"-",				"-",		False,	"pduExtPeak temp",				"Peak external device temperature in degrees celcius since last peak reset."),
	Register("snstyp",	5008,	1,	16,	False,	ASCII,	"pdu_measures",		0,		"ALL",			"-",				"-",		False,	"sensorType",					"Returns the detected sensor type, can be: T = temperature, H = humidity, I = dry switch input, O = switch output, R = residual current (mA), A = AC residual current (mA), D = DC residual current (mA), B = branch residual current (mA), S = error status, Y = activity, X = unused"),
	Register("snsval",	5024,	2,	16,	False,	FD,		"pdu_measures",		0,		"ALL",			"-",				"-",		False,	"sensorValue",					"Returns the sensor value. When [snstyp] = 'T', it denotes temperature in degree Celsius. When [snstyp] = 'H', it denotes humidity in percent. When [snstyp] = 'I', it denotes switch state as 0 or 1 or bitmap for different transition patterns."),
	Register("snsnme",	5056,	6,	16,	False,	ASCII,	"pdu_measures",		0,		"ALL",			"IPAPI",			"power",	False,	"sensorName",					"User definable name for sensors."),
	Register("snsenm",	5152,	18,	16,	False,	ASCII,	"pdu_measures",		240,	"ALL",			"IPAPI",			"power",	False,	"extendedSensorName",			"User definable name for sensors."),
	Register("exolnm",	6000,	18,	27,	True,	ASCII,	"ext_outlet_names",	240,	"ALL",			"IPAPI",			"power",	False,	"extendedOutletName",			"User configurable naming of individual outlets."),
	Register("viwatt",	9000,	2,	3,	False,	FD,		"virtual",			0,		"ALL",			"-",				"-",		False,	"virtualInputWatt",				"Input wattage (in kW), calculated by the device using current, voltage, and power factor measurements of a phase (phase is denoted by repeat/channel). Wattage = current * voltage * powerfactor / 100 / 1000"),
	Register("vivamp",	9006,	2,	3,	False,	FD,		"virtual",			0,		"ALL",			"-",				"-",		False,	"virtualInputVA",				"Input VA (volt-amps, in kVA), calculated by the device using current and voltage measurements of a phase (phase is denoted by repeat/channel). VA = current * voltage / 1000"),
	Register("vowatt",	9012,	2,	48,	False,	FD,		"virtual",			0,		"ALL",			"-",				"-",		False,	"virtualOutputWatt",			"Output wattage (in kW), calculated by the device using current, voltage, and power factor measurements of an outlet (outlet number is denoted by repeat/channel). Wattage = current * voltage * powerfactor / 100 / 1000"),
	Register("vovamp",	9108,	2,	48,	False,	FD,		"virtual",			0,		"ALL",			"-",				"-",		False,	"virtualOutputVA",				"Output VA (volt-amps, in kVA), calculated by the device using current and voltage measurements of an outlet (outlet number is denoted by repeat/channel). VA = current * voltage / 1000"),
	Register("honruf",	40000,	2,	1,	False,	INT,	"host",				130,	"IPAPI,WEBAPI",	"-",				"-",		False,	"nrUnitsFound",					"Result of scan command, denotes the number of devices on the SPBUS network."),
	Register("horist",	40002,	2,	1,	False,	INT,	"host",				136,	"IPAPI,WEBAPI",	"-",				"-",		False,	"ringStatus",					"SPBUS network architecture configuration. 0 = open ring network, 1 = closed ring network"),
	Register("hobrin",	40004,	2,	1,	False,	INT,	"host",				136,	"IPAPI,WEBAPI",	"-",				"-",		False,	"ringBreakLocation",			"Device index of the ring break location. Can be used to determine between which devices the ring is broken."),
	Register("hoscbu",	40100,	2,	1,	False,	INT,	"host",				130,	"-",			"IPAPI,WEBAPI",		"admin",	False,	"scanBus",						"Writing '1' to this register will invoke a scan."),
	Register("hocmrn",	40104,	2,	1,	False,	INT,	"host",				130,	"-",			"IPAPI,WEBAPI",		"admin",	False,	"renumAllFromN",				"Renumber devices on SPBUS network sequantially. Starts with the number written to this register on. Note that this overwrites all existing addresses!E.g.: writing '5' will renumber all devices on the SPBUS, giving them an iterating address number starting from address 5 (5, 6, 7, ...)"),
	Register("hocmrz",	40106,	2,	1,	False,	INT,	"host",				130,	"-",			"IPAPI,WEBAPI",		"admin",	False,	"renumAddrZeroC",				"Renumber all devices with address 0 in a sequential order."),
	Register("hocmra",	40110,	2,	1,	False,	INT,	"host",				242,	"-",			"IPAPI,WEBAPI",		"admin",	False,	"resetAllAlerts",				"Reset alerts of all devices"),
	Register("etclst",	31000,	1,	1,	False,	INT,	"ethernet",			0,		"WEBAPI",		"-",				"-",		False,	"linkStatus",					"Link state flags register: Link error = 0x01MII, link busy = 0x02, Changed state = 0x04, Connected = 0x08 (if not set, it's not connected)100Mbps mode = 0x10 (if not set then it's a 10mbps connection)Full-duplex mode = 0x20 (if not set, then it's a half-duplex connection)"),
	Register("etcnst",	31001,	1,	1,	False,	INT,	"ethernet",			0,		"WEBAPI",		"-",				"-",		False,	"networkStatus",				"Network state register: No cable = 0, DHCP acquiring = 1, DHCP bound = 2, Static = 3, DHCP static fallback = 4, Not configured = 5"),
	Register("etcip4",	31002,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"-",				"-",		False,	"currentIPv4",					"Active IPv4 address"),
	Register("etcnm4",	31003,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"-",				"-",		False,	"currentNetmask",				"Active netmask"),
	Register("etcgw4",	31004,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"-",				"-",		False,	"currentGateway",				"Active default gateway"),
	Register("etcdn1",	31005,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"-",				"-",		False,	"currentDNS1",					"Active primary DNS"),
	Register("etcdn2",	31006,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"-",				"-",		False,	"currentDNS2",					"Active secondary DNS"),
	Register("etchnm",	31007,	64,	1,	False,	ASCII,	"ethernet",			0,		"WEBAPI",		"-",				"-",		False,	"currentHostname",				"Active device hostname"),
	Register("etcp60",	31008,	16,	1,	False,	IPV6,	"ethernet",			244,	"WEBAPI",		"-",				"-",		False,	"currentIPv6addrll",			"Current IPv6 link-local address"),
	Register("etcp61",	31009,	16,	1,	False,	IPV6,	"ethernet",			244,	"WEBAPI",		"-",				"-",		False,	"currentIPv6addr1",				"Current IPv6 address 1 (usually used for private networks)"),
	Register("etcp62",	31010,	16,	1,	False,	IPV6,	"ethernet",			244,	"WEBAPI",		"-",				"-",		False,	"currentIPv6addr2",				"Current IPv6 address 2 (usually used globally)"),
	Register("etdhen",	31020,	1,	1,	False,	INT,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"dhcp",							"DHCP enable. non-zero integer = enabled, 0 = disabled"),
	Register("etdhfb",	31021,	1,	1,	False,	INT,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"dhcpFallbackEnable",			"DHCP fallback enable bit, allows the device to fallback to a static address.non-zero integer = enabled0 = disabled"),
	Register("etdhfd",	31022,	1,	1,	False,	INT,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"dhcpFallbackDelay",			"How long to wait (in seconds) for DHCP to work until it is assumed it won't and fallback to a static address."),
	Register("etipvs",	31023,	1,	1,	False,	INT,	"ethernet",			244,	"WEBAPI",		"WEBAPI",			"power",	True,	"ipVersion",					"Which IP version to use. 1 = IPv4 only, 2 = IPv6 only, 3 = IPv4/IPv6 Dual-stack"),
	Register("etsip4",	31024,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipv4Address",					"Static IPv4 address. Used as either the fallback or the static IPv4 address."),
	Register("etsnm4",	31025,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipv4SubnetMask",				"Static netmask. Used as either the fallback or the static netmask."),
	Register("etsgw4",	31026,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipv4Gateway",					"Static gateway. Used either the fallback or the static gateway."),
	Register("etsdn1",	31027,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipv4Gateway",					"Static primary DNS. Used as either the fallback or the static primary DNS."),
	Register("etsdn2",	31028,	4,	1,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipv4Gateway",					"Static secondary DNS. Used as either the fallback or the secondary DNS."),
	Register("etshnm",	31029,	64,	1,	False,	ASCII,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"hostname",						"Static hostname. Used for either the fallback or as the static hostname."),
	Register("etaips",	31030,	4,	3,	False,	IPV4,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipv4AcceptedIps",				"3 IP addresses that are allowed to connect to the device."),
	Register("etaipm",	31033,	1,	3,	False,	INT,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipv4AcceptedIpsPrefix",		"Denotes the accepted IP's subnet mask (using CIDR notation)."),
	Register("ethmod",	31036,	4,	1,	False,	INT,	"ethernet",			0,		"WEBAPI",		"WEBAPI",			"admin",	True,	"hPDUmode",						"hPDU mode flag register: HPDUMODE_CLASSIC = 0x00, HPDUMODE_HYBRID = 0x05, HPDUMODE_BRIDGE = 0x07, HPDUMODE_COLO_INFRA = 0x0D, HPDUMODE_COLO_ENDUSER = 0x15, HPDU_TWIN_MASTER = 0x27"),
	Register("etlsdm",	31037,	1,	1,	False,	INT,	"ethernet",			242,	"WEBAPI",		"WEBAPI",			"power",	True,	"Link Speed/Duplex Mode",		"Link Speed and Duplex Mode configuration. 0: autonegotiation, 1: 10Base-T Half Duplex, 2: 10Base-T Full Duplex, 3: 100Base-T Half Duplex, 4: 100Base-T Full Duplex"),
	Register("etip61",	31038,	16,	1,	False,	IPV6,	"ethernet",			244,	"WEBAPI",		"WEBAPI",			"power",	True,	"ipv6Address1",					"First static IPv6 address. Used as either the fallback or the static IPv6 address."),
	Register("etip62",	31039,	16,	1,	False,	IPV6,	"ethernet",			244,	"WEBAPI",		"WEBAPI",			"power",	True,	"ipv6Address2",					"Second static IPv6 address. Used as either the fallback or the static IPv6 address. Leave blank to disable."),
	Register("etip6s",	31040,	16,	3,	False,	IPV6,	"ethernet",			244,	"WEBAPI",		"WEBAPI",			"power",	True,	"ipv6AcceptedIPs",				"3 IPv6 addresses that are allowed to connect to the device."),
	Register("etip6p",	31043,	1,	3,	False,	INT,	"ethernet",			244,	"WEBAPI",		"WEBAPI",			"power",	True,	"ipv6AcceptedIPsPrefix",		"Denotes the accepted IP6's subnet mask (using CIDR notation)."),
	Register("etip6a",	31046,	1,	1,	False,	INT,	"ethernet",			244,	"WEBAPI",		"WEBAPI",			"power",	True,	"ipv6AutoconfEnabled",			"IPv6 Stateless local address auto configuration enable. 0 = disabled (use static address), 1 = enabled (obtain through ICMP6)"),
	Register("etip6f",	31047,	1,	1,	False,	INT,	"ethernet",			244,	"WEBAPI",		"WEBAPI",			"power",	True,	"ipv6StaticFallbackEnabled",	"IPv6 static IP fallback. 0 = disabled, 1 = enabled"),
	Register("iaenab",	31100,	1,	1,	False,	INT,	"ipapi",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipapiEnable",					"IPAPI enable. 1 = enabled, 0 = disabled"),
	Register("iarc4k",	31101,	16,	1,	False,	ASCII,	"ipapi",			0,		"WEBAPI",		"WEBAPI",			"power",	True,	"ipapiARC4key",					"ARC4 key used in the IPAPI exchange."),
	Register("hthpen",	31300,	1,	1,	False,	INT,	"http",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"httpInterfaceEnable",			"HTTP webinterface enable. 1 = enabled, 0 = disabled"),
	Register("hthsen",	31301,	1,	1,	False,	INT,	"http",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"httpsInterfaceEnable",			"HTTPS webinterface enable. 1 = enabled, 0 = disabled"),
	Register("hthppo",	31302,	2,	1,	False,	INT,	"http",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"httpInterfacePort",			"Port used for HTTP webinterface"),
	Register("hthspo",	31303,	2,	1,	False,	INT,	"http",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"httpsInterfacePort",			"Port used for HTTPS webinterface"),
	Register("snmpv1",	31600,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"v1Andv2Enable",				"Snmp v1 and v2 enable. 1 = enabled, 0 = disabled"),
	Register("snmpv3",	31601,	1,	1,	False,	INT,	"snmp",				242,	"WEBAPI",		"WEBAPI",			"power",	True,	"snmpv3Enable",					"SNMP v3 enable. 1 = enabled, 0 = disabled"),
	Register("sntrap",	31602,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"trapEnable",					"Snmp trap enable.1 = enabled, 0 = disabled"),
	Register("sndst1",	31603,	64,	1,	False,	ASCII,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"trapDestination1",				"Destination 1 for trap messages. Can be either a hostname or IP address."),
	Register("sndst2",	31604,	64,	1,	False,	ASCII,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"trapDestination2",				"Destination 2 for trap messages. Can be either a hostname or IP address."),
	Register("snmpro",	31605,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"snmpReadOnly",					"Snmp behavior enable. 2 = Read-only with scan, 1 = Read-only, 0 = disabled"),
	Register("snmplp",	31606,	2,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"snmpListenPort",				"Port on which snmp listens"),
	Register("snmotp",	31607,	2,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"snmpTrapPort",					"Port to which trap sends trap"),
	Register("sncmpb",	31608,	16,	1,	False,	ASCII,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"readCommunity",				"Snmp read community string"),
	Register("sncmpr",	31609,	16,	1,	False,	ASCII,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"writeCommunity",				"Snmp write community string"),
	Register("sncmtr",	31610,	16,	1,	False,	ASCII,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	True,	"trapCommunity",				"Trap community string"),
	Register("snisdn",	31612,	64,	1,	False,	ASCII,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"snmpDeviceName",				"Device name"),
	Register("snisdl",	31613,	64,	1,	False,	ASCII,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"snmpDeviceLocation",			"Device location"),
	Register("snisdc",	31614,	64,	1,	False,	ASCII,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"snmpDeviceContact",			"Device contact"),
	Register("sntrds",	31615,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapDeviceStatusCode",			"If set, the device will send device status code traps"),
	Register("sntrta",	31616,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapTempAlert",				"If set, the device will send temperature alert traps"),
	Register("sntric",	31617,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapInputCurrentAlert",		"If set, the device will send input current alert traps"),
	Register("sntroc",	31618,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapOutputCurrentAlert",		"If set, the device will send output current alert traps"),
	Register("sntriv",	31619,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapInputVoltageAlert",		"If set, the device will send input voltage alert traps"),
	Register("sntrod",	31620,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapOutputCurrentDropAlert",	"If set, the device will send output current drop alert traps"),
	Register("sntrid",	31621,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapInputCurrentDropAlert",	"If set, the device will send input current drop alert traps"),
	Register("sntraf",	31622,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapSnmpAuthFailure",			"If set, the device will send snmp authentication traps"),
	Register("sntrnc",	31623,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapNetworkConnectivity",		"Signifies network connectivity. Will send coldstart trap if set."),
	Register("sntrsc",	31624,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapSensorChangeAlert",		"If set, the device will send sensor change alert traps"),
	Register("sntrrc",	31625,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapRingStateChanged",			"If set, the device will send ring state change traps"),
	Register("sntrov",	31626,	1,	1,	False,	INT,	"snmp",				0,		"WEBAPI",		"WEBAPI",			"power",	False,	"trapOutletVoltageDropAlert",	"If set, the device will send outlet voltage drop alert traps"),
	Register("usname",	31700,	16,	5,	False,	ASCII,	"users",			0,		"WEBAPI,SNMP",	"WEBAPI",			"*",		False,	"usersUsername",				"Webapi and SNMPv3 username"),
	Register("uspaswd",	31710,	16,	5,	False,	ASCII,	"users",			0,		"*",			"WEBAPI",			"*",		False,	"usersPassword",				"Webapi password"),
	Register("login",	31700,	0,	0,	False,	ASCII,	"dummy",			0,		"-",			"-",				"-",		False,	"login",						"Fake register used internally"),
	Register("uspsea",	31720,	32,	5,	False,	INT,	"users",			242,	"-",			"WEBAPI",			"-",		False,	"passwordEncA",					"SNMPv3 authentication key"),
	Register("uspsea",	31730,	32,	5,	False,	INT,	"users",			242,	"-",			"WEBAPI",			"-",		False,	"passwordEncB",					"SNMPv3 encryption key"),
	# TODO: Parsing of register usacrd failed! (IPAPIProtocol) Data: b'\x00\x00' Error: unpack requires a bytes object of length 4
	Register("usacrd",	31740,	4,	5,	False,	INT,	"users",			0,		"WEBAPI",		"WEBAPI",			"admin",	False,	"usersRead",					"Defines the read access permissions of a userid where the userid level is denoted by channel"),
	Register("usacwr",	31750,	4,	5,	False,	INT,	"users",			0,		"WEBAPI",		"WEBAPI",			"admin",	False,	"usersWrite",					"Defines the write access permissions of a userid where the userid level is denoted by channel"),
	Register("usprau",	31760,	1,	5,	False,	INT,	"users",			242,	"WEBAPI,SNMP",	"WEBAPI",			"-",		False,	"usersAuthenticationProtocol",	"SNMPv3 authentication protocol"),
	Register("usprpr",	31770,	1,	5,	False,	INT,	"users",			242,	"WEBAPI,SNMP",	"WEBAPI",			"-",		False,	"usersPrivateProtocol",			"SNMPv3 encryption protocol"),
	Register("mbtcen",	32000,	1,	1,	False,	INT,	"",					0,		"WEBAPI",		"WEBAPI",			"power",	True,	"modbusEnable",					"Modbus enable. 1 = enabled, 0 = disabled"),
	Register("mbtcro",	32001,	1,	1,	False,	INT,	"",					0,		"WEBAPI",		"WEBAPI",			"power",	True,	"modbusReadOnly",				"If this is set to '1', then modbus is in read-only mode."),
	Register("mbtcpo",	32002,	2,	1,	False,	INT,	"",					0,		"WEBAPI",		"WEBAPI",			"power",	True,	"modbusPort",					"Port used for modbus communication")
]
