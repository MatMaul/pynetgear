pyNetgear
==============

pyNetgear provides an easy to use Python API to control your Netgear router. It uses the SOAP-api on modern Netgear routers to communicate. It is built by reverse engineering the requests made by the [NETGEAR Genie app](https://play.google.com/store/apps/details?id=com.dragonflow).

pyNetgear works with Python 2 and 3.

If you are connected to the network of the Netgear router, a host is optional.
If you are connected via a wired connection to the Netgear router, a password is optional.
The username defaults to admin.
The port defaults to 5000

It currently supports the following operations:

**login**<br>
Logs in to the router. Will return True or False to indicate success.

**get_attached_devices**<br>
Returns a list of named tuples describing the device signal, ip, name, mac, type and link_rate.

Installation
------------

You can install PyNetgear from PyPi using `pip3 install pynetgear` (use `pip` if you're still using Python 2).

Usage
-----
To test run from the console:
`$ python -m pynetgear [<pass>] [<host>] [<user>] [<port>]`

To use within your Python scripts:
```python
# All four parameters are optional
netgear = Netgear(password, host, username, port)

for i in netgear.get_attached_devices():
    print i
```

Supported routers
-----------------
It has been tested with the Netgear R6300 router and the Netgear WNDR4500 router. According to the NETGEAR Genie app description, the following routers should work:

 * Netgear R7000
 * Netgear R6300
 * Netgear R6250
 * Netgear R6200
 * Netgear R6100
 * Netgear Centria (WNDR4700, WND4720)
 * Netgear WNDR4500
 * Netgear WNDR4300
 * Netgear WNDR4000
 * Netgear WNDR3800
 * Netgear WNDR3700v3
 * Netgear WNDR3400v2
 * Netgear WNR3500Lv2
 * Netgear WNR2200
 * Netgear WNR2000v3
 * Netgear WNR2000v4 (Port 80)
 * Netgear WNR1500
 * Netgear WNR1000v2
 * Netgear WNR1000v3
 * Netgear WNDRMAC
 * Netgear WNR612v2
