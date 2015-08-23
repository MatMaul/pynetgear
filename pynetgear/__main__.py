import sys
from pynetgear import Netgear

netgear = Netgear(*sys.argv[1:])

devices = netgear.get_attached_devices()

if devices is None:
    print("Error communicating with the Netgear router")

else:
    for i in devices:
        print(i)
