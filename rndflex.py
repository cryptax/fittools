#!/usr/bin/env python
"""
__author__ = "Axelle Apvrille"
__status__ = "Beta"
__copyright__ = "Copyright 2015, Fortinet, Fortiguard Labs"
__license__ = "The MIT License (MIT)"

This script is provided for research only. Use at your own risk, and conform to law.

Short example:
$ python rndflex.py -b 16
a1 2e 89 da f5 db 5e 77 
c8 2d f1 7a d2 84 3c 21 

Troubleshooting:
1/ Use -v to understand where the problem occurs.
2/ The most frequent error originates from timeout issues. There may be several 
reasons to this:
- the tracker is not ready
- the tracker's batteries are too low
- the tracker is too far away
3/ It's long! Yes :( You can probably try to tune the timeouts.
"""

import usb.core
import time
import argparse

VID = 0x2687
PID = 0xfb01
megadump=0x0d
microdump=0x03
device = 0 # Global variable for USB device

def get_arguments():
    '''Read arguments for the program and returns the ArgumentParser'''
    parser = argparse.ArgumentParser(description='Using your Fitbit Flex as a source of entropy', prog='rndflex')
    parser.add_argument('-v', '--verbose', help='display packets and various debug messages', action='store_true')
    parser.add_argument('-o','--output', help='output file. Will overwrite the file. By default, goes to stdout', action='store')
    parser.add_argument('-b', '--bytes' , help='amount of random bytes to retrieve. Should be a multiple of 8', default='800', action='store')
    args = parser.parse_args()
    return args

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
                tag = 'Discovered Tracker Resp'
            if packet[1] == 0x02:
                tag = 'Finished Discovery Resp'
            if packet[1] == 0x06:
                tag = 'AirLink Test Resp'
            if packet[1] == 0x08:
                tag = 'Dongle Info Resp'

        print "[%02x] %25s: %s" % (endpoint, tag, ''.join('{:02x} '.format(x) for x in packet))

def connectUSB(VID=0x2687, PID=0xfb01):
    '''Connect to USB device and returns it    '''
    device = usb.core.find(idVendor=VID, idProduct=PID)
    if device is None:
        raise ValueError('Device not found')
    return device

def readResponse(endpoint=0x82, length=32, timeout=2000, verbose=False):
    '''Reads data of given length on USB endpoint.
    Will wait at most timeout seconds for data, if nothing is read, the timeout
    exception is caught and displayed.
    Assumes USB device is connected and set.
    '''
    assert device != 0, "Please call connectUSB() first"
    response=None
    try:
        response = device.read(endpoint, length, timeout)
        if verbose:
            displayPacket(response, endpoint)
    except usb.core.USBError as usbexception:
            if usbexception.errno != 110: # TIMEOUT
                raise
            else:
                print "Warning: no response (timeout=%d)" % (timeout)
    return response

def exhaustPipe(endpoint=0x82,length=32,timeout=2000, verbose=False):
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
            if verbose:
                displayPacket(response, endpoint)
        except usb.core.USBError as usbexception:
            if usbexception.errno != 110: # TIMEOUT
                raise
            # else 
            # we have exhausted the pipe
            break
    return fullResponse

def sendData(endpoint=0x02, data=0, timeout=500, verbose=False):
    '''Writes data on USB endpoint
    Assumes USB device (device) is connected and set
    '''
    assert device != 0, "Please call connectUSB() first"
    try:
        if verbose:
            displayPacket(data, endpoint)
        device.write(endpoint, data, timeout)
    except usb.core.USBError:
        print "sendData(): Resource busy usually means you need to unclaim the device"

# --------------------------------- Dongle messages --------------------
def getDongleInformation(timeout=500, verbose=False):
    '''Sends a Get Dongle Information request
    Reads the Get Dongle Information response - waiting at most for timeout seconds
    Displays the dongle version, MAC address and response packet
    Returns the response packet.
    '''
    if verbose:
        print "Get Dongle Info..."

    # send Get Dongle Info Request
    data = [ 0x02, 0x01 ]
    sendData(endpoint=0x02, data=data, timeout=timeout, verbose=verbose)

    # read Get Dongle Info Response
    response = device.read(0x82, 32, timeout)
    assert len(response) > 10, "Bad Dongle Info Response!"
    maj = response[2]
    min = response[3]
    mac = response[4:10]
    
    if verbose:
        print "Dongle: version %d.%d" % (maj, min)
        print "Dongle MAC address: %s " % (':'.join('{:02x}'.format(x) for x in mac))
        displayPacket(response, 0x82)

    return response

def dongleReset(timeout=500, verbose=False):
    '''Resets/disconnects the dongle.
    Usually, the dongle replies by a Cancel Discovery information message
    and possible by a Terminate Link.
    '''
    if verbose:
        print "dongleReset..."
    sendData(endpoint=0x02, data=[0x02, 0x02], timeout=timeout, verbose=verbose)

    # cancel discovery
    response = device.read(0x82, 32, timeout)
    if verbose:
        displayPacket(response, 0x82)

    # we might receive a Terminate Link, but this is optional
    # we exhaust the pipe to be in a clear state
    exhaustPipe(verbose=verbose)

def cancelDiscovery(timeout=500, verbose=False):
    '''Sends a cancel discovery message'''
    if verbose:
        print "Cancel Discovery..."
    sendData(endpoint=0x02, data=[0x02, 0x05], timeout=timeout, verbose=verbose)
    
    # we expect a cancel discovery status message
    readResponse(verbose=verbose)

def discover(timeout=500, verbose=False):
    '''Sends a device discovery message
    Waits for a start discovery information response
    And responses from trackers.
    When all trackers have answered, cancel discovery.
    '''
    if verbose:
        print "Discover..."
    # UUID of Fitbit
    # then service 0xfb00, 0xfb001, 0xfb002
    data = [ 0x1a,0x04,0xba,0x56,0x89,0xa6,0xfa,0xbf,0xa2,0xbd,0x01,0x46,0x7d,0x6e,0x00,0x00,0xab,0xad,0x00,0xfb,0x01,0xfb,0x02,0xfb,0xa0,0x0f ]
    sendData(endpoint=0x02, data=data, timeout=timeout, verbose=verbose)

    # read responses
    # we should receive: StartDiscovery, messages from trackers, and 
    # amount of trackers found
    while True:
       response = device.read(0x82, 32, 4000)
       if response is None:
           if verbose:
               print "Warning: we have exhausted the pipe"
           break
       if verbose:
           displayPacket(response, 0x82)
       if response[1] == 0x02:
           if verbose:
               print "Amount of trackers found: %d " % (response[2])
           break
    
    cancelDiscovery(timeout, verbose=verbose)


def togglePipe(value=0, timeout=500, verbose=False):
    '''Send Toggle Tx Pipe
    value is 0 for disable, 1 for enable
    '''
    if verbose:
        print "Toggle Pipe..."
    data = [ 0x03, 0x08 ]
    data.extend([value])
    sendData(endpoint=0x02, data=data, timeout=timeout, verbose=verbose)

    # c0 0b
    readResponse(endpoint=0x81,timeout=10000,verbose=verbose)


def establishLink(trackerId='516706E749CF', addrType=1, serviceUuid='4f1e', timeout=500, verbose=False):
    '''Sends an Establish Link request to a given tracker, and reads the response'''
    if verbose:
        print "Establish Link with tracker %s and serviceUUID=%s" % (trackerId, serviceUuid)
    endpoint = 0x02
    data = [ 0x00, 0x06 ] 
    data.extend(list(bytearray.fromhex(trackerId)))
    data.extend([addrType])
    data.extend(list(bytearray.fromhex(serviceUuid)))
    data[0] = len(data) # 0B
    sendData(endpoint, data, timeout, verbose)

    # in this one, the tracker responds 'EstablishLink called'
    readResponse(verbose=verbose) # 20 01 EstablishLink called

    # we need to wait longer for ACK
    readResponse(timeout=5000, verbose=verbose) # EstablishLink ack

    # we need to wait even longer for this one
    readResponse(timeout=8000, verbose=verbose) # GAP_LINK_ESTABLISHED_EVENT

    # 02 07 Now it is established!
    readResponse(verbose=verbose)

def terminateAirLink(timeout=500, verbose=False):
    '''Terminates the air link, reads the potential responses'''
    sendData(endpoint=0x02, data=[0x02, 0x07], timeout=timeout, verbose=verbose)
    exhaustPipe(verbose=verbose)

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


def initAirLink(timeout=500, verbose=False):
    '''Init Air Link message'''
    if verbose:
        print "Init Air Link..."
    #data = [ 0xc0, 0x0a, 0x0a, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c ]
    #sendData(endpoint=0x01,data=data,timeout=timeout, verbose=verbose)
    data = [ 0x0a, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc8, 0x00 ]
    packet = prepareTrackerPacket(0x0a, data, useful_len=0x0c)
    sendData(endpoint=0x01, data=packet, timeout=timeout, verbose=verbose)

    # AirLink test response up: 08 06 00 00 00 0xc8...
    readResponse(endpoint=0x82,timeout=10000, verbose=verbose)
    
    # AirLink is initialized c0 14 0c ...
    readResponse(endpoint=0x81, verbose=verbose)



# ---------------- Helper funcs -------------------------------
def getAirLink(verbose=False):
    '''A helper func that resets the link and re-initializes air link'''
    dongleReset(verbose=verbose)
    discover(verbose=verbose)
    establishLink(verbose=verbose)
    togglePipe(value=1, verbose=verbose)
    initAirLink(verbose=verbose) 

# --------------------- "Hacks" --------------------------

def getRandom(seed=[], get_air_link=True, verbose=False):
    '''Using the tracker like a random number generator
    There is no guarantee this will provide good entropy'''
    if get_air_link:
        getAirLink(verbose)

    # payload needs to be at least of length 8
    payload = seed
    for i in range(len(payload), 8):
        payload.extend([i])
    assert len(payload) >= 8, "payload is too small"

    # let's send the client challenge
    useful_len = 2 + len(payload)
    packet = prepareTrackerPacket(id=0x50, data=payload, useful_len=useful_len)
    sendData(endpoint=0x01,data=packet,timeout=500,verbose=verbose)

    # tracker is expected to respond with a tracker challenge
    response = exhaustPipe(endpoint=0x81, timeout=2000, verbose=verbose)
    
    # the random part is 8 byte long
    if verbose:
        print ''.join('{:02x} '.format(x) for x in response[2:10])

    return response[2:10]

def writeRandom2file(filename, amount=800, verbose=True):
    '''Getting amount of random bytes'''
    loops = amount / 8
    if filename is not None:
        f = open(filename,'wb')

    # first call must initialize air link
    random_buffer = getRandom(get_air_link=True, verbose=verbose)
    if filename is None:
        print ''.join('{:02x} '.format(x) for x in random_buffer)
    else:
        f.write(bytearray(random_buffer))

    # subsequent calls use established air link
    for i in range(1, loops):
        random_buffer = getRandom(get_air_link=False, verbose=verbose)
        if filename is None:
            print ''.join('{:02x} '.format(x) for x in random_buffer)
        else:
            f.write(bytearray(random_buffer))

    if filename is not None:
        f.close()


# main ---------------------------
if __name__ == "__main__":
    args = get_arguments()
    device = connectUSB()
    writeRandom2file(filename=args.output, verbose=args.verbose, amount=int(args.bytes))
