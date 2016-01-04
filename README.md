# fittools

This repository contains research tools for the Fitbit Flex.
They are released under the MIT License (https://opensource.org/licenses/MIT). 
Use at your own risk.

* rndflex.py: a Python research script to use the Fitbit Flex as a Random Number Generator.

* donglelock.py: lock your screen when you remove the dongle. Requires python-pyudev

* trackerlock.py: locks your screen when you walk away from the dongle (on your laptop)

* dongle-version.py: quick utility to report the version of your USB dongle. 

# Requirements

* Python 2.7
* Pyudev 1.0+: http://sourceforge.net/projects/pyusb

# Install

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

