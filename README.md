# fittools

This repository contains research tools for the Fitbit Flex.
They are released under the MIT License (https://opensource.org/licenses/MIT). 
Use at your own risk.

## Tools using Fitbit's USB dongle

* rndflex.py: a Python research script to use the Fitbit Flex as a Random Number Generator.

* donglelock.py: lock your screen when you remove the dongle. Requires python-pyudev

* trackerlock.py: locks your screen when you walk away from the dongle (on your laptop)

* dongle-version.py: quick utility to report the version of your USB dongle.


### Requirements

* Python 2.7
* Pyudev 1.0+: http://sourceforge.net/projects/pyusb (python-usb on Debian/Ubuntu)



### Install

1. In /etc/udev/rules.d/99-fitbit.rules:

```
SUBSYSTEM=="usb", ATTR{idVendor}=="2687", ATTR{idProduct}=="fb01", OWNER="YOURUSER", GROUP="plugdev", SYMLINK+="fitbit", MODE="0666"
```

and customize YOURUSER to the user who will use the Fitbit device on the host.

2. Load the new udev config:

```
$ sudo udevadm control --reload-rules
$ sudo udevadm trigger
```

3. Install requirements

4. Play :) For example:

```
$ python talk2flex.py
```

## Tool using a standard BLE USB dongle

* read-battery.py: utility to read the battery level of a Fitbit Flex using a standard BLE USB dongle.

Disclaimer: this tool is for 'research'. Using it repeatedly may affect your battery life and communication to your tracker. Use at your own risk.

### Requirements

* a Bluetooth Low Energy (BLE 4.0) USB dongle (does **not** work with Fitbit's USB dongle)
* [gattlib](https://bitbucket.org/OscarAcena/pygattlib)

### Usage

```bash
python read-battery.py --target XX:XX:XX:XX:XX:XX [--verbose] [--help]
```

where the target supplies the MAC address of the tracker to read the battery level from.

### Troubleshooting

`RuntimeError: Invalid device!`

- Make sure your USB dongle works
- Unplug it, replug it
- Is this a BLE USB dongle?
- The tool does **not** work with a Fitbit USB dongle

`connect: Connection refused (111)`

- Is some other program connected to your tracker? (gatttool? Mobile phone?)
- Make sure to disconnect all your devices from the tracker

`RuntimeError: Could not update HCI connection: Operation not permitted`

- Run the program as root (sudo)

**What the MAC address of my tracker?**

Scan your devices with a BLE scanner. You can for instance use your BLE USB dongle:

```bash
$ sudo hcitool lescan
LE Scan ...
xx:xx:xx:xx:xx:xx Flex
```

or, if your phone supports BLE, you can use an application such as [nRF Connect](https://play.google.com/store/apps/details?id=no.nordicsemi.android.mcp).


**Any other issue?**

- Please report them. In particular, I have assumed that Battery Level is readable on handle 0x1b and configurable on 0x1c, because that is the case on both my trackers, but perhaps it's different on yours (I haven't been able to test extensively). Please supply your tracker's model and the exact errors you get.


