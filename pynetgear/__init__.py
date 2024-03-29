"""Module to communicate with Netgear routers using the SOAP v2 API."""
# flake8: noqa

from .router import Device, Netgear
from .const import ALLOW, BLOCK, DEFAULT_HOST, DEFAULT_USER, DEFAULT_PORT
