#!/usr/bin/env python

"""
__author__ = "Axelle Apvrille"
__status__ = "Beta"
__copyright__ = "Copyright 2015, Fortinet, Fortiguard Labs"
__license__ = "The MIT License (MIT)"

This utility helps work with Fitbit fitness trackers
Connect the USB dongle to your host, and place your tracker nearby.
Use responsibly.
Use at your own risk!!!
"""

import usb.core
import usb.util
import sys
import time
import argparse
import random

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

# Message display ----------------------------------------
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

def displayCommandId(packet, endpoint):
    assert len(packet) > 1, "Packet length too small"
    tag = ''
    if packet[0] == 0x20 and packet[1] == 0x01:
        return 'Status Message'
    else:
        if endpoint == 0x01:
            if packet[0] == 0xc0 and packet[1] == 0x04:
                tag = 'Handle Secret Req'
            if packet[0] == 0xc0 and packet[1] == 0x05:
                tag = 'Alert User Req'
            if packet[0] == 0xc0 and packet[1] == 0x06:
                tag = 'Display Code Req'
            if packet[0] == 0xc0 and packet[1] == 0x09:
                tag = 'Echo Req'
            if packet[0] == 0xc0 and packet[1] == 0x0a:
                tag = 'Init AirLink Req'
            if packet[0] == 0xc0 and packet[1] == 0x10:
                tag = 'Get Dump Req'
            if packet[0] == 0xc0 and packet[1] == 0x24:
                tag = 'Data Transmit Req'
        if endpoint == 0x81:
            if packet[0] == 0xc0 and packet[1] == 0x02:
                tag = 'Ack Resp'
            if packet[0] == 0xc0 and packet[1] == 0x03:
                tag = 'Error Resp'
            if packet[0] == 0xc0 and packet[1] == 0x05:
                tag = 'Alert User Resp'   
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
            if packet[1] == 0x02:
                tag = 'Finished Discovery Resp'
            if packet[1] == 0x06:
                tag = 'AirLink Test Resp'
            if packet[1] == 0x08:
                tag = 'Dongle Info Resp'
    return tag


def displayPacket(packet, endpoint):
    '''Displays status messages as strings if possible, 
    otherwise, displays the message as bytes'''
    assert len(packet) > 1, "Packet length too small"
    if packet[0] == 0x20 and packet[1] == 0x01:
        print "[%02x] Status Message          : %s" % (endpoint, ''.join(chr(i) for i in packet[2:]))
    else:
        tag=displayCommandId(packet, endpoint)
        if endpoint == 0x82 and packet[1] == 0x03 and len(packet) >= 19:
            tracker = Tracker(packet)
            print tracker

        print "[%02x] %25s: %s" % (endpoint, tag, ''.join('{:02x} '.format(x) for x in packet))

def displayUsefulContent(packet, endpoint):
    '''Displays the packet only the useful length part'''
    ul = 0
    if packet[0] == 0xc0:
        ul = packet[0x20-1]
    else:
        ul = packet[0]
    tag = displayCommandId(packet, endpoint)
    return "[%02x] %25s: '%s'" % (endpoint, tag, ''.join(map(chr, packet[2:ul])))

# 
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

# --------------------------------- Classes --------------------

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

    def __str__(self):
        return "TrackerId: %s AddrType: %d RSSI: %d Attr: %s SUUID: %s" % (''.join('{:02x} '.format(x) for x in self.trackerid), self.addrtype, self.rssi, ''.join('{:02x} '.format(x) for x in self.attr), ''.join('{:02x} '.format(x) for x in self.suuid)) 


class megadump(object):
    '''This class represents a megadump packet '''
    type = 0x0d

    def __init__(self, dump):
        assert len(dump)>16, "This is not a valid dump"
        self.device_type = dump[0]
        self.device_version = dump[1]
        self.seq_counter = dump[6:10]
        self.model = dump[10:16]
        self.encrypted = dump[16:]

    def getDeviceName(self):
        options = { 0x28 : "Flex",
                    0xf4 : "Zip",
                    0x26 : "One" }
        if self.device_type in options:
            return options[self.device_type]
        return 'unknown'

    def __str__(self):
        return "Device Type: %s\nVersion    : %d\nSeq Counter: %s\nModel      : %s\nEncrypted blob:\n%s" % (self.getDeviceName(), self.device_version, ''.join('{:02x} '.format(x) for x in self.seq_counter), ''.join('{:02x} '.format(x) for x in self.model), displayLongHex(self.encrypted))

class minidump(object):
    ''' This class represents a microdump/minidump packet'''
    type = 0x03

    def __init__(self, dump):
        assert len(dump) == 0x7b, "Invalid minidump length"
        assert dump[0] == 0x30, "This is not a minidump"
        self.seq_counter = dump[6:10]
        self.model = dump[10:16]
        self.encrypted = dump[16:121]

    def __str__(self):
        return "Seq Counter: %s\nModel      : %s\nEncrypted blob:\n%s" % (''.join('{:02x} '.format(x) for x in self.seq_counter), ''.join('{:02x} '.format(x) for x in self.model), displayLongHex(self.encrypted))

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


def togglePipe(value=0, timeout=500, show_packets=False):
    '''Send Toggle Tx Pipe
    value is 0 for disable, 1 for enable
    '''
    if show_packets:
        print "Toggle Pipe..."
    data = [ 0x03, 0x08 ]
    data.extend([value])
    sendData(endpoint=0x02, data=data, timeout=timeout, show_packets=show_packets)

    # c0 0b
    readResponse(endpoint=0x81,timeout=10000,show_packets=show_packets)


def establishLink(trackerId, addrType, serviceUuid, timeout=500, show_packets=False):
    '''Sends an Establish Link request to a given tracker, and reads the response'''
    if show_packets:
        print "Establish Link with tracker %s and serviceUUID=%s" % (trackerId, serviceUuid)
    endpoint = 0x02
    data = [ 0x00, 0x06 ] 
    data.extend(list(bytearray.fromhex(trackerId)))
    data.extend([addrType])
    data.extend(list(bytearray.fromhex(serviceUuid)))
    data[0] = len(data) # 0B
    sendData(endpoint, data, timeout, show_packets)

    # in this one, the tracker responds 'EstablishLink called'
    readResponse(show_packets=show_packets) # 20 01 EstablishLink called

    # we need to wait longer for ACK
    readResponse(timeout=5000, show_packets=show_packets) # EstablishLink ack

    # we need to wait even longer for this one
    readResponse(timeout=8000, show_packets=show_packets) # GAP_LINK_ESTABLISHED_EVENT

    # 02 07 Now it is established!
    readResponse(show_packets=show_packets)

def terminateAirLink(timeout=500, show_packets=False):
    '''Terminates the air link, reads the potential responses'''
    sendData(endpoint=0x02, data=[0x02, 0x07], timeout=timeout, show_packets=show_packets)
    exhaustPipe(show_packets=show_packets)

# ------------------------------------- Tracker messages ---------------------------

def prepareTrackerPacket(id=0x01, data=[0x00]*29, useful_len=2):
    '''Prepares a tracker packet c0 ...
    Expands payload with trailing 0x00 if necessary
    The useful packet length must include the length of C0 id so
    it is payload length + 2.
    
    This does not send nor print the packet. It only returns it.
    '''
    assert useful_len <= 0xff, "Implementation does not support length on more than a byte"
    packet = [0xc0, id]
    packet.extend(data)
    if len(data) < 29:
        packet.extend([0x00] * (29-len(data)))
    packet.extend([useful_len])
    return packet


def initAirLink(timeout=500, show_packets=False):
    '''Init Air Link message'''
    if show_packets:
        print "Init Air Link..."
    #data = [ 0xc0, 0x0a, 0x0a, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c ]
    #sendData(endpoint=0x01,data=data,timeout=timeout, show_packets=show_packets)
    data = [ 0x0a, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc8, 0x00 ]
    packet = prepareTrackerPacket(0x0a, data, useful_len=0x0c)
    sendData(endpoint=0x01, data=packet, timeout=timeout, show_packets=show_packets)

    # AirLink test response up: 08 06 00 00 00 0xc8...
    readResponse(endpoint=0x82,timeout=10000, show_packets=show_packets)
    
    # AirLink is initialized c0 14 0c ...
    readResponse(endpoint=0x81, show_packets=show_packets)


def getDump(dumptype=0x0d, timeout=500,show_packets=False):
    '''
    Sends a request for a given dumptype
    and reads the answer until it has retrieved the full dump 
    Returns it.
    '''
    packet = prepareTrackerPacket(id=0x10, data=[dumptype], useful_len=3)
    sendData(endpoint=0x01, data=packet, timeout=timeout, show_packets=show_packets)

    dump = []
    while True:
       response = device.read(0x81, 32, 2000)
       if response is None:
           if show_packets:
               print "Warning: we have exhausted the pipe"
           break
       if not (response[0] == 0xc0 and response[1] == 0x41) and not (response[0] == 0xc0 and response[1] == 0x42):
           # the start dump response is not part
           # the end dump is not part either
           dump.extend(response[:response[31]])
       if show_packets:
           displayPacket(response, 0x81)
       if response[0] == 0xc0 and response[1] == 0x42:
           if show_packets:
               print "End of Dump packet"
           break

    return dump

def echo(data=[0x0],timeout=500,show_packets=False):
    '''According to my research, echo is 0x09, despite
    http://samdmarshall.com/blog/fitbit_re.html
    It is consistent with 
    https://bitbucket.org/benallard/galileo/wiki/Communicationprotocol

    Sends an Echo Request and reads the response.
    '''
    if show_packets:
        print "Sending Echo..."
    data = prepareTrackerPacket(id=0x09, data=data,useful_len=len(data)+2)
    sendData(endpoint=0x01,data=data,timeout=timeout,show_packets=show_packets)
    response = exhaustPipe(endpoint=0x81, timeout=timeout, show_packets=show_packets)

    if response is not None and len(response) >= 0x20:
        ul = response[0x20-1]
        print "Echo Message: %s" % (''.join(map(chr, response[2:ul])))
        


# ---------------- Helper funcs -------------------------------
def getAirLink(show_packets=False):
    '''A helper func that resets the link and re-initializes air link'''
    
    global mytracker
    if mytracker is None:
        if show_packets:
            "Trying automatic selection of tracker"
        dongleReset(show_packets=show_packets)
        listOfTracker = discover(show_packets=show_packets)

        assert len(listOfTracker) == 1, "We dont know which tracker to establish link to"

        mytracker = listOfTracker[0]
        
    print "Establishing link with %s..." % (mytracker)
    establishLink(show_packets=show_packets, trackerId=''.join('{:02x}'.format(x) for x in mytracker.trackerid), addrType=mytracker.addrtype, serviceUuid=''.join('{:02x}'.format(x) for x in mytracker.suuid))
    togglePipe(value=1, show_packets=show_packets)
    initAirLink(show_packets=show_packets) 

def sendExhaustReinit(data=[], send_timeout=500, read_timeout=10000,show_packets=False):
    '''
    1. re-init air link with tracker
    2. send data to tracker using send_timeout
    3. exhaust pipe using read_timeout
    '''
    getAirLink(show_packets=False)
    sendData(endpoint=0x01,data=data,timeout=send_timeout, show_packets=show_packets)
    response = exhaustPipe(endpoint=0x81, show_packets=show_packets, timeout=read_timeout)
    if response is not None:
        print "THERE IS A RESPONSE !"
    
# --------------------- "Hacks" --------------------------

def getRandom(seed=[], get_air_link=True, show_packets=False):
    '''Using the tracker like a random number generator
    There is no guarantee this will provide good entropy'''
    if get_air_link:
        getAirLink(False)

    # payload needs to be at least of length 8
    payload = seed
    for i in range(len(payload), 8):
        payload.extend([i])
    assert len(payload) >= 8, "payload is too small"

    # let's send the client challenge
    useful_len = 2 + len(payload)
    packet = prepareTrackerPacket(id=0x50, data=payload, useful_len=useful_len)
    sendData(endpoint=0x01,data=packet,timeout=500,show_packets=show_packets)

    # tracker is expected to respond with a tracker challenge
    response = exhaustPipe(endpoint=0x81, timeout=2000, show_packets=show_packets)
    
    # the random part is 8 byte long
    if show_packets:
        print ''.join('{:02x} '.format(x) for x in response[2:10])

    return response[2:10]

# Functions called by the menu ------------------------------
def doDiscover(show_packets=False):
    print "Discovering trackers nearby..."
    dongleReset(show_packets=show_packets)
    listOfTracker = discover(show_packets=show_packets)
    for t in listOfTracker:
        print t

def selectTracker(show_packets=False):
    print "Getting list of available trackers..."
    dongleReset(show_packets=show_packets)
    listOfTracker = discover(show_packets=show_packets)

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


def getMegadump(show_packets=False):
    print "Initializing Air Link..."
    getAirLink(show_packets=show_packets)
    print "Getting tracker data..."
    packet = getDump(megadump.type, show_packets=show_packets)
    print "Received tracker data: "
    print megadump(packet)

def getMinidump(show_packets=False):
    print "Initializing Air Link..."
    getAirLink(show_packets=show_packets)
    print "Getting tracker firmware..."
    packet = getDump(microdump.type, show_packets=show_packets)
    print "Received tracker firmware: "
    print minidump(packet)

def doRng(show_packets=False):
    print "Initializing air link..."
    random_buffer = getRandom(get_air_link=True, show_packets=show_packets)
    print "Getting random data..."
    print ''.join('{:02x} '.format(x) for x in random_buffer)
    for i in range(0, 100):
        random_buffer = getRandom(get_air_link=False, show_packets=show_packets)
        print ''.join('{:02x} '.format(x) for x in random_buffer)

def doDongleInfo(show_packets=False):
    '''Sends a Get Dongle Information request
    Reads the Get Dongle Information response - waiting at most for timeout seconds
    Displays the dongle version, MAC address and response packet
    Returns the response packet.
    '''
    print "Get Dongle Info :"

    # send Get Dongle Info Request
    data = [ 0x02, 0x01 ]
    sendData(endpoint=0x02, data=data, timeout=500, show_packets=show_packets)

    # read Get Dongle Info Response
    response = device.read(0x82, 32, 500)
    if show_packets:
        displayPacket(response, 0x82)
    assert len(response) > 10, "Bad Dongle Info Response!"
    maj = response[2]
    min = response[3]
    mac = response[4:10]
    
    print "Dongle                    : version %d.%d" % (maj, min)
    print "Dongle MAC address: %s " % (':'.join('{:02x}'.format(x) for x in mac))

def doDongleStatus(show_packets=False):
    print "Get Dongle Status :"
    
    # send Get Dongle Status
    data = [ 0x02, 0x11 ]
    sendData(endpoint=0x02, data=data, timeout=500, show_packets=show_packets)

    # read responses
    scan = False
    disc = False
    ble = False
    for i in range(0, 6):
        response = readResponse(endpoint=0x82, show_packets=show_packets)
        if response[0] == 0x20 and response[1] == 0x01:
            ul = response[0]
            message = ''.join(map(chr, response[2:ul]))
            if scan:
                print "Scan state\t\t: %s" % (message)
            if disc:
                print "Service discovery state\t: %s" % (message)
            if ble:
                print "Bluetooth state\t\t: %s" % (message)
            if message.startswith('scanInProgress:'):
                scan = True
            else:
                scan = False
            if message.startswith('svcDiscoveryState:'):
                disc = True
            else:
                disc = False
            if message.startswith('dongleBLEState:'):
                ble = True
            else:
                ble = False 
            #print "scan %d disc %d ble %d " % (scan, disc, ble)
    exhaustPipe(endpoint=0x82, show_packets=show_packets)

def doEcho(show_packets=False):
    text = raw_input("Enter short string to echo: ");
    text = text[:20]

    print "Initializing air link with tracker..."
    getAirLink(show_packets=False)

    data = []
    for i in range(0, len(text)):
        data.extend([ord(text[i])])

    print "Sending echo with '%s'" % (text)
    echo(data=data, show_packets=show_packets)

def doHandleSecret(show_packets=False, display=True):
    '''Testing the command Handle Secret'''
    print "Initializing air link with tracker..."
    getAirLink(show_packets=False)

    if display:
        print "Sending Handle Secret - Display..."
    else:
        print "Sending Handle Secret - Clear..."
    
    data = prepareTrackerPacket(id=0x04, data=[display],useful_len=3)
    sendData(endpoint=0x01,data=data,show_packets=show_packets)
    response = exhaustPipe(endpoint=0x81, show_packets=show_packets)
    print displayUsefulContent(response, endpoint=0x81)


def doAlert(show_packets=False):
    print "Initializing air link with tracker..."
    getAirLink(show_packets=False)

    print "Sending Alert User..."
    data = prepareTrackerPacket(id=0x05, data=[],useful_len=2)
    sendData(endpoint=0x01,data=data,show_packets=show_packets)

    response = exhaustPipe(endpoint=0x81, show_packets=show_packets)
    print displayUsefulContent(response, endpoint=0x81)

def doDisplayCode(show_packets=False, code='1234'):
    print "Initializing air link with tracker..."
    getAirLink(show_packets=False)

    print "Sending Display Code: %s..." % (code)
    data = []
    for i in range(0, len(code)):
        data.extend([ord(code[i])])
    packet = prepareTrackerPacket(id=0x06, data=data,useful_len=len(data)+2)
    sendData(endpoint=0x01,data=packet,show_packets=show_packets)

    response = exhaustPipe(endpoint=0x81, show_packets=show_packets)
    print displayUsefulContent(response, endpoint=0x81)

def doReset(show_packets=False):
    print "Resetting dongle..."
    dongleReset(show_packets=show_packets)

def doQuit(show_packets=False):
    print "Bye!"
    quit()


# User Interface ---------------------------------------------------
def get_arguments():
    '''Read arguments for the program and returns the ArgumentParser'''
    parser = argparse.ArgumentParser(description='Standalone tool to talk to the Fitbit Flex', prog='talk2flex')
    parser.add_argument('-v', '--verbose', help='display packets and various debug messages', action='store_true')
    parser.add_argument('-o','--output', help='output file', action='store')
    args = parser.parse_args()
    return args

def displayMenu(show_packets=False):
    if show_packets:
        print "displayMenu()"

    print "=== talk2flex - a FitBit Flex Linux utility tool ===";
    print "Dongle commands:"
    print "1-  Unclaim dongle"
    print "2-  Get dongle info"
    print "3-  Get dongle status"

    print "Tracker commands: "
    print "5-  Detect trackers"
    print "6-  Select tracker"
    print "7-  Get tracker data"
    print "8-  Get firmware data"
    print "9-  Echo"
    print "10- Handle Secret"
    print "11- Alert"
    print "12- Display Code"
    print "14- RNG"

    print "Misc: "
    print "15- Reset"
    print "16- Quit"

    try:
        response = int(raw_input("Your choice? "))
    except ValueError:
        print "Please enter a number!"
        quit()

    global device
    if (device == 0):
        device = connectUSB()
    
    actions = { 1 : unclaimFitbit,
                2: doDongleInfo,
                3: doDongleStatus,
                5: doDiscover,
                6: selectTracker,
                7: getMegadump,
                8: getMinidump,
                9: doEcho,
                10: doHandleSecret,
                11: doAlert,
                12: doDisplayCode,
                14: doRng,
                15: doReset,
                16: doQuit,
    }

    assert response in actions, "Unavailable choice"

    actions[response](show_packets=show_packets)


# Main ---------------------------
if __name__ == "__main__":
    args = get_arguments()
    while True:
        displayMenu(show_packets=args.verbose)



