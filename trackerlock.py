#!/usr/bin/env python

'''
__author__ = "Axelle Apvrille"
__status__ = "Alpha"
__copyright__ = "Copyright 2015, Fortinet, Fortiguard Labs"
__license__ = "MIT License"

Customize the lock() function with your own command to perform when the
tracker is away
'''
import argparse
import usb.core
import usb.util
import sys
import time
import subprocess

__version__ = '0.1'
previous_rssi = 0 
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

def unclaimFitbitDongle(show_packets=False):
    '''Unclaim a fitbit device'''
    global device
    device = connectUSB()
    for interface in range(0,2):
        detach(device, interface, show_packets)
        unclaim(device, interface, show_packets)

# Message display (for debugging)
def displayLongHex(buffer, bytes_per_line=16):
    '''Formats an hexadecimal string with bytes per line at most
    Example:
    28 02 00 00 01 00 44 04 00 00 d2 c0 56 2e 15 07 
    19 7f 2b f6 f6 49 f9 f2 a5 fc 88 38 18 a6 9c 50 
    fb 01 00 00 
    '''
    hexstring = ''.join('{:02x} '.format(x) for x in buffer)
    newstring = ''
    hexstring_len = len(hexstring)
    pos = 0
    while pos < hexstring_len:
        maxpos = pos + (3*bytes_per_line)
        if maxpos >= hexstring_len:
            maxpos = hexstring_len
        newstring = newstring + hexstring[pos:maxpos] + '\n'
        pos = pos + (3*bytes_per_line)
    return newstring

def displayPacket(packet, endpoint):
    '''Displays status messages as strings if possible, 
    otherwise, displays the message as bytes'''
    assert len(packet) > 1, "Packet length too small"
    if packet[0] == 0x20 and packet[1] == 0x01:
        print "[%02x] Status Message          : %s" % (endpoint, ''.join(chr(i) for i in packet[2:]))
    else:
        tag=''
        if endpoint == 0x01:
            if packet[0] == 0xc0 and packet[1] == 0x09:
                tag = 'Echo Req'
            if packet[0] == 0xc0 and packet[1] == 0x0a:
                tag = 'Init AirLink Req'
            if packet[0] == 0xc0 and packet[1] == 0x10:
                tag = 'Get Dump Req'
            if packet[0] == 0xc0 and packet[1] == 0x24:
                tag = 'Data Transmit Req'
        if endpoint == 0x81:
            if packet[0] == 0xc0 and packet[1] == 0x03:
                tag = 'Error Resp'
            if packet[0] == 0xc0 and packet[1] == 0x09:
                tag = 'Echo Resp'    
            if packet[0] == 0xc0 and packet[1] == 0x12:
                tag = '1st block ack Resp'
            if packet[0] == 0xc0 and packet[1] == 0x13:
                tag = 'Next block ack Resp'
            if packet[0] == 0xc0 and packet[1] == 0x14:
                tag = 'AirLink Init Resp'
            if packet[0] == 0xc0 and packet[1] == 0x0b:
                tag = 'Toggle Tx Resp'
            if packet[0] == 0xc0 and packet[1] == 0x41:
                tag = 'Start Dump Resp'
            if packet[0] == 0xc0 and packet[1] == 0x42:
                tag = 'End Dump Resp'
        if endpoint == 0x02:
            if packet[1] == 0x06:
                tag = 'Establish Link Req'
            if packet[1] == 0x08:
                tag = 'Toggle Tx Req'
            if packet[1] == 0x04:
                tag = 'Start Discovery Req'
            if packet[1] == 0x05:
                tag = 'Cancel Discovery Req'
            if packet[1] == 0x01:
                tag = 'Get Dongle Info Req'
            if packet[1] == 0x07:
                tag = 'Terminate AirLink'
        if endpoint == 0x82:
            if packet[1] == 0x04:
                tag = 'Establish Link Resp'
            if packet[1] == 0x03:
                if (len(packet) < 19):
                    tag = 'Bad discovered tracker resp'
                else:
                    tag = 'Discovered Tracker Resp'
                    tracker = Tracker(packet)
                    print tracker

            if packet[1] == 0x02:
                tag = 'Finished Discovery Resp'
            if packet[1] == 0x06:
                tag = 'AirLink Test Resp'
            if packet[1] == 0x08:
                tag = 'Dongle Info Resp'

        print "[%02x] %25s: %s" % (endpoint, tag, ''.join('{:02x} '.format(x) for x in packet))

# talk 2 flex
def readResponse(endpoint=0x82, length=32, timeout=2000, show_packets=False):
    '''Reads data of given length on USB endpoint.
    Will wait at most timeout seconds for data, if nothing is read, the timeout
    exception is caught and displayed.
    Assumes USB device is connected and set.
    '''
    assert device != 0, "Please call connectUSB() first"
    response=None
    try:
        response = device.read(endpoint, length, timeout)
        if show_packets:
            displayPacket(response, endpoint)
    except usb.core.USBError as usbexception:
            if usbexception.errno != 110: # TIMEOUT
                raise
            else:
                print "Warning: no response (timeout=%d)" % (timeout)
    return response

def exhaustPipe(endpoint=0x82,length=32,timeout=2000, show_packets=False):
    '''Reads incoming data packets of given length on USB endpoint.
    Loops reading until there is no more to be read after timeout seconds.
    Assumes USB device (device) is connected and set'''
    assert device != 0, "Please call connectUSB() first"
    fullResponse = None
    while True:
        try:
            response = device.read(endpoint, length, timeout)
            if response is None:
                break
            else:
                if fullResponse is None:
                    fullResponse = []
                fullResponse.extend(response)
            if show_packets:
                displayPacket(response, endpoint)
        except usb.core.USBError as usbexception:
            if usbexception.errno != 110: # TIMEOUT
                raise
            # else 
            # we have exhausted the pipe
            break
    return fullResponse

def sendData(endpoint=0x02, data=0, timeout=500, show_packets=False):
    '''Writes data on USB endpoint
    Assumes USB device (device) is connected and set
    '''
    assert device != 0, "Please call connectUSB() first"
    try:
        if show_packets:
            displayPacket(data, endpoint)
        device.write(endpoint, data, timeout)
    except usb.core.USBError:
        print "sendData(): Resource busy usually means you need to unclaim the device"

# --------------------------------- Dongle messages --------------------

def dongleReset(timeout=500, show_packets=False, display=False):
    '''Resets/disconnects the dongle.
    Usually, the dongle replies by a Cancel Discovery information message
    and possible by a Terminate Link.
    '''
    if display:
        print "resetting dongle..."
    sendData(endpoint=0x02, data=[0x02, 0x02], timeout=timeout, show_packets=show_packets)

    # cancel discovery
    response = device.read(0x82, 32, timeout)
    if show_packets:
        displayPacket(response, 0x82)

    # we might receive a Terminate Link, but this is optional
    # we exhaust the pipe to be in a clear state
    exhaustPipe(endpoint=0x82, show_packets=show_packets, timeout=4000)

def cancelDiscovery(timeout=500, show_packets=False):
    '''Sends a cancel discovery message'''
    if show_packets:
        print "Cancel Discovery..."
    sendData(endpoint=0x02, data=[0x02, 0x05], timeout=timeout, show_packets=show_packets)
    
    # we expect a cancel discovery status message
    readResponse(show_packets=show_packets)

class Tracker(object):
    def __init__(self, id, addr, rssi, attr, suuid):
        self.trackerid = id
        self.addrtype = addr
        self.rssi = rssi
        self.attr = attr
        self.suuid = suuid

    def __init__(self, packet):
        assert packet[0] != 0xc0, "This is not a dongle message"
        assert packet[1] == 0x03, "This is not a discovered tracker response"
        assert len(packet) >= 19, "Bad length for discovered tracker response"
        self.trackerid = packet[2:8]
        self.addrtype = packet[8]
        self.rssi = packet[9]
        self.attr = packet[10:12]
        self.suuid = packet[17:19]

    def __eq__(self, other):
        '''Comparing two trackers - trackers are equal if the fields are the same except RSSI which might change'''
        if self.trackerid == other.trackerid and self.addrtype == other.addrtype and self.attr == other.attr and self.suuid == other.suuid:
            return True
        return False

    def __str__(self):
        return "TrackerId: %s AddrType: %d RSSI: %d Attr: %s SUUID: %s" % (''.join('{:02x} '.format(x) for x in self.trackerid), self.addrtype, self.rssi, ''.join('{:02x} '.format(x) for x in self.attr), ''.join('{:02x} '.format(x) for x in self.suuid)) 

def discover(timeout=500, show_packets=False, cancel=True):
    '''Sends a device discovery message
    Waits for a start discovery information response
    And responses from trackers.
    When all trackers have answered, cancel discovery.
    '''
    listOfTrackers = []
    
    # UUID of Fitbit
    # then service 0xfb00, 0xfb001, 0xfb002
    data = [ 0x1a,0x04,0xba,0x56,0x89,0xa6,0xfa,0xbf,0xa2,0xbd,0x01,0x46,0x7d,0x6e,0x00,0x00,0xab,0xad,0x00,0xfb,0x01,0xfb,0x02,0xfb,0xa0,0x0f ]
    sendData(endpoint=0x02, data=data, timeout=timeout, show_packets=show_packets)

    # read responses
    # we should receive: StartDiscovery, messages from trackers, and 
    # amount of trackers found
    while True:
       response = device.read(0x82, 32, 4000)
       if response is None:
           if show_packets:
               print "Warning: we have exhausted the pipe"
           break
       
       if show_packets:
           displayPacket(response, 0x82)
       if response[1] == 0x02:
           if show_packets:
               print "Amount of trackers found: %d " % (response[2])
           break
       if response[0] != 0xc0 and response[1] == 0x03:
           tracker = Tracker(response)
           if show_packets:
               print tracker
           listOfTrackers.append(tracker)
    
    # in most cases, you want to properly finish the discovery
    if cancel:
        cancelDiscovery(timeout, show_packets=show_packets)
    return listOfTrackers

def selectTracker(verbose=False):
    print "Getting list of available trackers..."
    dongleReset(show_packets=False)
    listOfTracker = discover(show_packets=False)

    if (len(listOfTracker) > 0):
        num = 1
        for t in listOfTracker:
            print "%d- %s" % (num, t)
            num += 1
        try:
            choice = int(raw_input("Select tracker's num: "))
        except ValueError:
            print "Please enter a number!"
            quit()
        assert choice >= 1 and choice <= len(listOfTracker), "Please select a valid tracker"
        
        global mytracker
        mytracker = listOfTracker[choice-1]

        global previous_rssi
        previous_rssi = mytracker.rssi

def lock(verbose=False):
    '''Locks the screen
    Customize this function with your own command to lock the screen (or other action)
    '''
    if verbose:
        print "Locking screen"
    subprocess.call(["mate-screensaver-command", "--lock"])
    quit()

def monitorTracker(delay=30, movement=30, verbose=False):
    '''We check the tracker hasn't moved away: comparison is done with the 
    previous RSSI value. 
    If tracker has moved away, we lock the screen.
    Note that RSSI decreases if the tracker is covered
    Possible Alternative: compare with 2 or more previous values.
    '''
    while True:
        listOfTracker = discover(timeout=500, show_packets=False, cancel=True)
        found = False
        for t in listOfTracker:
            if t == mytracker:
                found = True
                global previous_rssi
                if t.rssi < (previous_rssi - movement):
                    print "Tracker has moved away!!! (RSSI=%d)" % (t.rssi)
                    lock(verbose)
                else:
                    previous_rssi = t.rssi
                    if verbose:
                        print "Tracker found: current RSSI=%d" % (t.rssi)
        if not found:
            print "Tracker not found!!"
            lock(verbose)
        else:
            # we've found it, let's test in a while
            if verbose:
                print "Sleeping for %d seconds" % (delay)
            time.sleep(delay)


def get_arguments():
    parser = argparse.ArgumentParser(description='Tool that detects Fitbit tracker moves away', epilog = 'Version '+__version__+' - Greetz from Axelle Apvrille')
    parser.add_argument('-v', '--verbose', help='get more detailed messages', action='store_true')
    parser.add_argument('-t', '--delay', help='how often we poll the tracker in seconds', type=int, action='store',default=30)
    parser.add_argument('-m', '--movement', help='how much the RSSI must decrement to be detected as away', type=int, action='store', default=30)
    args = parser.parse_args()
    
    return args

if __name__ == "__main__":
    args = get_arguments()
    unclaimFitbitDongle(show_packets=False)
    selectTracker(verbose=args.verbose)
    monitorTracker(delay=args.delay,movement=args.movement,verbose=args.verbose)

