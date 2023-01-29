#!/usr/bin/python

import enum
import time
import paho.mqtt.client as mqtt

from hlapi.hlapi import HLAPI
from hlapi.DeviceManager import DeviceManager
from hlapi.managers.MultiReadWrite import MultiReadWrite


SLEEP_SEC = int(1)  # seconds

THRESHOLD_POWER_LOWER = int(75)   # watt
THRESHOLD_POWER_UPPER = int(100)  # watt

SENSOR_INTERFACE = {
    "192.168.1.220": {
        "webapi_port": 80,
        "webapi_user": "super",
        "webapi_pass": "super",
        "ipapi_key": "0000000000000000"
    }
}


class PowerPlugState(str, enum.Enum):
    OFF = "OFF"
    ON = "ON"


class PowerPlug:
    def __init__(self) -> None:
        self.mqtt_client = mqtt.Client()
        self.state = PowerPlugState.OFF
        self._switch_plug(PowerPlugState.OFF)

    def transition_on(self) -> None:
        if self.state == PowerPlugState.ON:
            return
        self.state = PowerPlugState.ON
        self._switch_plug(self.state)

    def transition_off(self) -> None:
        if self.state == PowerPlugState.OFF:
            return
        self.state = PowerPlugState.OFF
        self._switch_plug(self.state)
    
    def retransmit_state(self):
        self._switch_plug(self.state)    
    
    def _switch_plug(self, state: PowerPlugState):
        self.mqtt_client.connect('localhost', 1883, 60)
        self.mqtt_client.publish('zigbee2mqtt/Lufttrockner/set', '{"state": "%s"}' % state.value)
        self.mqtt_client.disconnect()
        print("Plug -> %s" % state.value)
    

def read_power_data(hlapi: HLAPI) -> float:
    deviceManager = DeviceManager(hlapi)
    deviceManager.loadInterfaces(SENSOR_INTERFACE)

    multiReadWrite = MultiReadWrite(hlapi, deviceManager.devices)

    # retrieve current
    try:
        currentRead = multiReadWrite.readSingle('imcrac')
        current = list(currentRead.values())[0]['data'][0]
    except:
        return -1.0
    
    # retrieve voltage
    try:
        voltageRead = multiReadWrite.readSingle('imvoac')
        voltage = list(voltageRead.values())[0]['data'][0]
    except:
        return -1.0

    return current * voltage


def main():
    hlapi = HLAPI(debug=False)
    plug = PowerPlug()

    cnt = 0
    while True:
        power = read_power_data(hlapi)
        print('Power: %.1f Watt' % power)
        
        if plug.state == PowerPlugState.OFF and power > THRESHOLD_POWER_UPPER:
            plug.transition_on()
        if plug.state == PowerPlugState.ON and power < THRESHOLD_POWER_LOWER:
            plug.transition_off()

        time.sleep(SLEEP_SEC)
        cnt += 1 
        if cnt == 60:
            cnt = 0
            plug.retransmit_state()


if __name__ == '__main__':
    main()
