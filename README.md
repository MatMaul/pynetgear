pyNetgear
==============

pyNetgear provides an easy to use Python API to control your Netgear router. It uses the SOAP-api on modern Netgear routers to communicate. It is built by reverse engineering the requests made by the [NETGEAR Genie app](https://play.google.com/store/apps/details?id=com.dragonflow).

pyNetgear works with Python 2 and 3.

It currently supports the following operations:
 
**login**<br>
Logs in to the router. Will return True or False to indicate success.

**get_attached_devices**<br>
Returns a list of named tuples describing the device signal, ip, name, mac, type and link_rate 

Usage
-----
To test run from the console:
`$ python pynetgear.py <host> <user> <pass>`

To use within your Python scripts:
```python
netgear = Netgear(host, username, password)

for i in netgear.get_attached_devices():
    print i
```

Supported routers
-----------------
It has been tested with the Netgear R6300 router but according to the NETGEAR Genie app description it should support the following routers:

 * R7000
 * R6300
 * R6250
 * R6200
 * R6100
 * Centria (WNDR4700, WND4720)
 * WNDR4500
 * WNDR4300
 * WNDR4000
 * WNDR3800
 * WNDR3700v3
 * WNDR3400v2
 * WNR3500Lv2
 * WNR2200
 * WNR2000v3
 * WNR1500
 * WNR1000v2
 * WNR1000v3
 * WNDRMAC
 * WNR612v2
