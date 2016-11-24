#!/usr/bin/env python

'''
__author__ = "Axelle Apvrille"
__version__ = "0.1"
__copyright__ = "Copyright 2016, Fortinet, Fortiguard Labs"
__license__ = "The MIT License (MIT)"

Requirements:
   Software:
      gattlib: https://bitbucket.org/OscarAcena/pygattlib
      example:
         sudo apt-get install libboost-python-dev libboost-all-dev python-setuptools
         sudo pip install gattlib

   Hardware:
      This works with a standard BLE USB dongle. It does not work with Fitbit's USB dongle.
      Example: 0a12:0001 Cambridge Silicon Radio, Ltd Bluetooth Dongle (HCI mode)
      Make sure your BLE dongle works and is configured:
        sudo hciconfig
        sudo hciconfig hci0 up
        sudo hcitool lescan

Run:
  $ sudo python read-battery.py --target aa:bb:cc:dd:ee:ff 
'''

import argparse
import struct
from gattlib import GATTRequester
from threading import Event

class RequesterWithNotif(GATTRequester):
    def __init__(self, thread, verbose, *args):
        GATTRequester.__init__(self, *args)
        self.event_thread = thread
        self.verbose = verbose

    def on_notification(self, handle, data):
        if self.verbose:
            print "> on_notification()"
            print "\tFrom handle=0x%02x, value=%s" % (handle, data[0].encode('hex'))

        # Set the internal flag to true. All threads waiting for it to become true are awakened. 
        self.event_thread.set()
        if self.verbose:
            print "< on_notification()"
        
class BatteryLevel(object):
    def __init__(self, address='xx:xx:xx:xx:xx:xx', verbose=False):
        ''' if you get error: RuntimeError: Invalid device!
        make sure your dongle works 
        '''
        self.event_thread = Event()
        self.verbose = verbose
        self.req = RequesterWithNotif(self.event_thread, verbose, address, False)
        
        
    def connect(self):
        ''' if you get error: connect: Connection refused (111)
        make sure the tracker isn't already connected to another device
        
        if you get error: RuntimeError: Could not update HCI connection: Operation not permitted
        run program as root!
        '''
        if self.verbose:
            print("> connect(): Connecting...")
        self.req.connect(wait=True, channel_type='random')
        if self.verbose:
            print("< connect(): Connected")

    def disconnect(self):
        self.req.disconnect()
        if self.verbose:
            print("Disconnected")

    def read_battery(self, value_handle=0x1b, notif_handle=0x1c):
        '''Battery level is stored in a characteristic whose (standard) UUID is 00002a19-0000-1000-8000-00805f9b34fb.
        On the Fitbit Flex, this characteristic is accessible from handle 0x1b.

        The battery level is only supplied once battery level notifications have been enabled (otherwise, you actually
        always get 0 as battery level). To request notifications, we have to modify handle 0x1c - which
        is Client Characteristic Configuration, and set to 0x0001 i.e enable notifications

        If you haven't connected yet, this function will do it for you and disconnect at the end.
        '''
        if self.verbose:
            print "> read_battery(): value_handle=0x%02x notif_handle=0x%02x" % (value_handle, notif_handle)

        auto=False # indicator if we need to disconnect here or not
        if not self.req.is_connected():
            self.connect()
            auto=True

        # to read battery level, we need to enable battery level notification
        if self.verbose:
            print "\tConfiguring tracker to get battery level notification"
        self.req.write_by_handle(notif_handle,  str(bytearray([0x01, 0x00])))

        if self.verbose:
            print "\tWaiting for battery level notification..."
        self.event_thread.wait()
        
        # reading by handle, because it does not work by UUID
        if self.verbose:
            print "\tReading battery level..."
        try:
            data = self.req.read_by_handle(value_handle)
            # data is something like: ['\x00']
            if self.verbose:
                print "\tGATT response: %s" % (data[0].encode('hex'))

            # converting response to battery level percentage
            value = struct.unpack("B", data[0])[0]
            if self.verbose:
                print "\tValue: %2.0f percent" % (value)
            assert value >=0 and value <= 100, "Battery level beyond range. Strange"
        
        except RuntimeError:
            value = 'UNAVAILABLE'
            if self.verbose:
                print "\tCaught RuntimeError exception"

        if auto:
            if self.verbose:
                print "\tDisconnect required"
            self.disconnect()

        if self.verbose:
            print "< read_battery()"
        return value

def get_arguments():
    parser = argparse.ArgumentParser(description='Utility to read battery level of Fitbit Flex', prog='read-battery')
    parser.add_argument('-v','--verbose', help='verbose',action='store_true')
    parser.add_argument('-t','--target',help='mac address format xx:xx:xx:xx:xx:xx',action='store')
    args=parser.parse_args()
    return args


if __name__ == '__main__':
    print '============ Fitbit Flex Battery Level Utility ========='
    args = get_arguments()
    
    if args.target:
        r = BatteryLevel(address=args.target,verbose=args.verbose)
    else:
        r = BatteryLevel(verbose=args.verbose)
        
    level = r.read_battery()
    
    if level == 'UNAVAILABLE':
        print "Battery level percentage not available"
    else:
        print "Battery level percentage %2.1f %%" % (level)
