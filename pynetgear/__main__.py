#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Run PyNetgear from the command-line."""
import sys
from pynetgear import Netgear


def main():
    """Scan for devices and print results."""
    netgear = Netgear(*sys.argv[1:])

    devices = netgear.get_attached_devices()

    if devices is None:
        print("Error communicating with the Netgear router")

    else:
        for i in devices:
            print(i)

if __name__ == '__main__':
    main()
