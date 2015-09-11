#!/usr/bin/env python

'''
__author__ = "Axelle Apvrille"
__status__ = "Alpha"
__copyright__ = "Copyright 2015, Fortinet, Fortiguard Labs"
__license__ = "MIT License"

Interesting refs:
https://stackoverflow.com/questions/469243/how-can-i-listen-for-usb-device-inserted-events-in-linux-in-python
http://pyudev.readthedocs.org/en/latest/api/pyudev.glib.html#pyudev.glib.MonitorObserver
'''
import glib
from pyudev import Context, Monitor
from pyudev.glib import GUDevMonitorObserver as MonitorObserver
import re
import subprocess
import argparse

monitored_idVendor = ''
monitored_idProduct = ''
monitored_serial = ''
monitored_path = ''
verbose = False
__version__ = '0.2'


def get_arguments():
    parser = argparse.ArgumentParser(description='Tool that detects removal of USB devices', epilog = 'Version '+__version__+' - Greetz from Axelle Apvrille')
    parser.add_argument('-v', '--verbose', help='get more detailed messages', action='store_true')
    args = parser.parse_args()

    global verbose
    verbose = args.verbose
    return args

def display_device_attributes(device):
    print 'VendorId       : {0}'.format(device.attributes.get('idVendor'))
    print 'ProductId      : {0}'.format(device.attributes.get('idProduct'))
    print 'Manufacturer: {0}'.format(device.attributes.get('manufacturer'))
    print 'Product         : {0}'.format(device.attributes.get('product'))
    print 'SerialNo        : {0}'.format(device.attributes.get('serial'))


def add_event(observer, device):
    global verbose
    if verbose:
        print 'Adding device (monitoring %s.%s)' % (monitored_idVendor, monitored_idProduct)

    if device.attributes.get('idVendor') == monitored_idVendor and device.attributes.get('idProduct') == monitored_idProduct and device.attributes.get('serial') == monitored_serial:
        # recording the device path
        display_device_attributes(device)
        print "You have just added the monitored device!"
        global monitored_path
        monitored_path = device.device_path
    

def remove_event(observer, device):
    global verbose
    if verbose: 
        print 'Removing device (monitoring %s.%s)' % (monitored_idVendor, monitored_idProduct)

    if device.device_path == monitored_path:
        if verbose:
            display_device_attributes(device)
        print "You have just removed the monitored device!"
        

def monitor():
    context = Context()
    monitor = Monitor.from_netlink(context)
    monitor.filter_by(subsystem='usb')  
    observer = MonitorObserver(monitor)
    observer.connect('device-removed', remove_event)
    observer.connect('device-added', add_event)
    monitor.start()
    glib.MainLoop().run()

def select_devices():
    context = Context()
    devices = context.list_devices(subsystem="usb") 
    num = 1
    for dev in devices:
        print "%02d- %s %s SerialNo: %s %s" % (num, dev.attributes.get('idVendor'), dev.attributes.get('idProduct'), dev.attributes.get('serial'), dev.attributes.get('manufacturer'))
        num += 1
    try:
        choice = int(raw_input("Select device: [1-%d] " % (num)))
    except ValueError:
        print "Please enter a number!"
        quit()

    assert choice >=1 and choice <= num, "Please enter a valid number"

    num = 1
    for dev in devices:
        if num == choice:
            global verbose
            if verbose: 
                print "Selected device: "
                display_device_attributes(dev)
            global monitored_idVendor
            monitored_idVendor = dev.attributes.get('idVendor')
            global monitored_idProduct 
            monitored_idProduct = dev.attributes.get('idProduct')
            global monitored_serial
            monitored_serial = dev.attributes.get('serial')
            global monitored_path
            monitored_path = dev.device_path
            break
        num +=1

if __name__ == '__main__':
    args = get_arguments()
    select_devices()
    monitor()
