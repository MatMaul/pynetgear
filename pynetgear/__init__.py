"""Module to communicate with Netgear routers using the SOAP v2 API."""
from __future__ import print_function

import re
from collections import namedtuple
import logging
import xml.etree.ElementTree as ET
from datetime import timedelta

import requests

DEFAULT_HOST = 'routerlogin.net'
DEFAULT_USER = 'admin'
DEFAULT_PORT = 5000
_LOGGER = logging.getLogger(__name__)

Device = namedtuple(
    "Device", ["signal", "ip", "name", "mac", "type", "link_rate"])


class Netgear(object):
    """Represents a session to a Netgear Router."""

    def __init__(self, password=None, host=DEFAULT_HOST, user=DEFAULT_USER,
                 port=DEFAULT_PORT):
        """Initialize a Netgear session."""
        self.soap_url = "http://{}:{}/soap/server_sa/".format(host, port)
        self.username = user
        self.password = password
        self.port = port
        self.logged_in = host is DEFAULT_HOST

    def login(self):
        """
        Login to the router.

        Will be called automatically by other actions.
        """
        _LOGGER.info("Login")

        message = SOAP_LOGIN.format(session_id=SESSION_ID,
                                    username=self.username,
                                    password=self.password)

        success, _ = self._make_request(
            ACTION_LOGIN, message, False)

        self.logged_in = success

        return self.logged_in

    def get_attached_devices(self):
        """
        Return list of connected devices to the router.

        Returns None if error occurred.
        """
        _LOGGER.info("Get attached devices")

        def parse_response(response):
            try:
                result = re.search(REGEX_ATTACHED_DEVICES, response).group(1)
            except (AttributeError):
                _LOGGER.error("Error parsing respone: %s", response)
                return False, None
            else:
                return True, result

        success, response = self._make_request(
            ACTION_GET_ATTACHED_DEVICES,
            SOAP_ATTACHED_DEVICES.format(session_id=SESSION_ID))

        if not success:
            return None

        parsable, raw = parse_response(response)

        if not parsable:
            return None

        # Netgear inserts a double-encoded value for "unknown" devices
        decoded = raw.replace(UNKNOWN_DEVICE_ENCODED, UNKNOWN_DEVICE_DECODED)

        entries = decoded.split("@")
        devices = []

        # First element is the total device count
        if len(entries) > 1:
            entry_count = convert(entries.pop(0), int)
        else:
            _LOGGER.error("Error parsing device-list: %s", entries)
            return None

        if(entry_count != len(entries)):
            _LOGGER.warning(
                """Number of devices should \
                 be: %d but is: %d""", entry_count, len(entries))

        for entry in entries:
            info = entry.split(";")

            if len(info) == 0:
                continue

            # Not all routers will report link type and rate
            if len(info) == 7:
                link_type = info[4]
                link_rate = convert(info[5], int)
                signal = convert(info[6], int)
            elif len(info) == 4:
                signal = 100
                link_type = None
                link_rate = 0
            else:
                _LOGGER.warning("Unexpected entry: %s", info)
                continue

            ipv4, name, mac = info[1:4]

            devices.append(Device(signal, ipv4, name, mac, link_type,
                                  link_rate))

        return devices

    def get_traffic_meter(self):
        """
        Return dict of traffic meter stats.

        Returns None if error occurred.
        """
        _LOGGER.info("Get traffic meter")

        def parse_text(text):
            """
                there are three kinds of values in the returned data
                This function parses the different values and returns
                (total, avg), timedelta or a plain float
            """
            def tofloats(lst): return (float(t) for t in lst)
            try:
                if "/" in text:  # "6.19/0.88" total/avg
                    return tuple(tofloats(text.split('/')))
                elif ":" in text:  # 11:14 hr:mn
                    hour, mins = tofloats(text.split(':'))
                    return timedelta(hours=hour, minutes=mins)
                else:
                    return float(text)
            except ValueError:
                return None
        success, response = self._make_request(
            ACTION_GET_TRAFFIC_METER,
            SOAP_TRAFFIC_METER.format(session_id=SESSION_ID))

        if not success:
            return None

        # parse XML, see capture/trafficmeter.response
        root = ET.fromstring(response)
        namespace = {
            "m": "urn:NETGEAR-ROUTER:service:DeviceConfig:1",
            "SOAP-ENV": "http://schemas.xmlsoap.org/soap/envelope/"
        }
        data = root.find(".//m:GetTrafficMeterStatisticsResponse", namespace)
        trafficdict = {t.tag: parse_text(t.text) for t in data}
        return trafficdict

    def _make_request(self, action, message, try_login_after_failure=True):
        """Make an API request to the router."""
        # If we are not logged in, the request will fail for sure.
        if not self.logged_in and try_login_after_failure:
            if not self.login():
                return False, ""

        headers = _get_soap_header(action)

        try:
            req = requests.post(
                self.soap_url, headers=headers, data=message, timeout=10)

            success = _is_valid_response(req)

            if not success and try_login_after_failure:
                self.login()

                req = requests.post(
                    self.soap_url, headers=headers, data=message, timeout=10)

                success = _is_valid_response(req)

            return success, req.text

        except requests.exceptions.RequestException:
            _LOGGER.exception("Error talking to API")

            # Maybe one day we will distinguish between
            # different errors..
            return False, ""


def _get_soap_header(action):
    return {"SOAPAction": action}


def _is_valid_response(resp):
    return (resp.status_code == 200 and
            "<ResponseCode>000</ResponseCode>" in resp.text)


def convert(value, to_type, default=None):
    """Convert value to to_type, returns default if fails."""
    try:
        return default if value is None else to_type(value)
    except ValueError:
        # If value could not be converted
        return default


ACTION_LOGIN = "urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate"
ACTION_GET_ATTACHED_DEVICES = \
    "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetAttachDevice"
ACTION_GET_TRAFFIC_METER = \
    "urn:NETGEAR-ROUTER:service:DeviceConfig:1#GetTrafficMeterStatistics"

REGEX_ATTACHED_DEVICES = r"<NewAttachDevice>(.*)</NewAttachDevice>"

# Until we know how to generate it, give the one we captured
SESSION_ID = "A7D88AE69687E58D9A00"

SOAP_LOGIN = """<?xml version="1.0" encoding="utf-8" ?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header>
<SessionID xsi:type="xsd:string"
  xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance">{session_id}</SessionID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<Authenticate>
  <NewUsername>{username}</NewUsername>
  <NewPassword>{password}</NewPassword>
</Authenticate>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

SOAP_ATTACHED_DEVICES = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAPSDK1="http://www.w3.org/2001/XMLSchema"
  xmlns:SOAPSDK2="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:SOAPSDK3="http://schemas.xmlsoap.org/soap/encoding/"
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header>
<SessionID>{session_id}</SessionID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<M1:GetAttachDevice xmlns:M1="urn:NETGEAR-ROUTER:service:DeviceInfo:1">
</M1:GetAttachDevice>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

SOAP_TRAFFIC_METER = """
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAPSDK1="http://www.w3.org/2001/XMLSchema"
  xmlns:SOAPSDK2="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:SOAPSDK3="http://schemas.xmlsoap.org/soap/encoding/"
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header>
<SessionID>{session_id}</SessionID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<M1:GetTrafficMeterStatistics\
xmlns:M1="urn:NETGEAR-ROUTER:service:DeviceConfig:1"></M1:GetTrafficMeterStatistics>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

UNKNOWN_DEVICE_DECODED = '<unknown>'
UNKNOWN_DEVICE_ENCODED = '&lt;unknown&gt;'
