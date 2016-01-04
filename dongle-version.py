#!/usr/bin/env python

"""
__author__ = "Axelle Apvrille"
__copyright__ = "Copyright 2015, Fortinet, Fortiguard Labs"
__date__ = "December 4, 2015"
__license__ = "The MIT License (MIT)"

This utility works on Linux and returns the maj/min version number
of your dongle's firmware.
Plug in your dongle, and run the program.

This has NOT been tested over Windows.

Use responsibly.
Use at your own risk!!!

Requires pyusb: http://sourceforge.net/projects/pyusb
"""

import usb.core
import usb.util
import sys
import argparse

VID = 0x2687
PID = 0xfb01
device = 0 # Global variable for USB device
mytracker = None # Global variable for selected tracker

# USB connection -----------------------------------------------

def connectUSB(VID=0x2687, PID=0xfb01):
    '''Connect to USB device and returns it    '''
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise ValueError('Device not found')
    return dev

def detach(dev, interface=0, show_packets=False):
    '''Detach the interface'''
    if dev.is_kernel_driver_active(interface):
        if show_packets:
            print "Detaching kernel driver for interface %d" % (interface)
        dev.detach_kernel_driver(interface)

def unclaim(dev, interface=0, show_packets=False):
    if show_packets:
        print "Unclaiming interface %d " % (interface)
    usb.util.release_interface(dev, interface)

def unclaimFitbit(show_packets=False):
    '''Unclaim a fitbit device'''
    global device
    device = connectUSB()
    for interface in range(0,2):
        detach(device, interface, show_packets)
        unclaim(device, interface, show_packets)

def sendData(endpoint=0x02, data=0, timeout=500):
    '''Writes data on USB endpoint
    Assumes USB device (device) is connected and set
    '''
    assert device != 0, "Please call connectUSB() first"
    try:
        device.write(endpoint, data, timeout)
    except usb.core.USBError:
        print "sendData(): Resource busy usually means you need to unclaim the device"

def getFirmwareVersion(show_packets=False):
    if show_packets:
        print "Getting dongle's firmware version..."

    # send Get Dongle Info Request
    data = [ 0x02, 0x01 ]
    sendData(endpoint=0x02, data=data, timeout=500)

    # read Get Dongle Info Response
    response = device.read(0x82, 32, 500)
    assert len(response) > 10, "Bad Dongle Info Response!"
    maj = response[2]
    min = response[3]
    return maj, min

def get_arguments():
    '''Read arguments for the program and returns the ArgumentParser'''
    parser = argparse.ArgumentParser(description='Program that gets the version number of the Fitbit USB Dongle', prog='dongle-version')
    args = parser.parse_args()
    return args


# Main ---------------------------
if __name__ == "__main__":
    args = get_arguments()

    # checking dongle version
    unclaimFitbit()
    maj, min = getFirmwareVersion()
    print "Your dongle's firmware is v%d.%d" % (maj, min)
    

    


