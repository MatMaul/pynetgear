"""Module to communicate with Netgear routers using the SOAP v2 API."""
from __future__ import print_function

from io import StringIO
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
    "Device", ["signal", "ip", "name", "mac", "type", "link_rate",
               "allow_or_block", "device_type", "device_model",
               "ssid", "conn_ap_mac"])


class Netgear(object):
    """Represents a session to a Netgear Router."""

    def __init__(self, password=None, host=None, user=None, port=None,
                 ssl=False, url=None):
        """Initialize a Netgear session."""
        if not url and not host and not port:
            url = autodetect_url()

        if url:
            self.soap_url = url + "/soap/server_sa/"
        else:
            if not host:
                host = DEFAULT_HOST
            if not port:
                port = DEFAULT_PORT
            scheme = "https" if ssl else "http"
            self.soap_url = "{}://{}:{}/soap/server_sa/".format(scheme,
                                                                host, port)

        if not user:
            user = DEFAULT_USER

        self.username = user
        self.password = password
        self.port = port
        self.logged_in = False

    def login(self):
        """
        Login to the router.

        Will be called automatically by other actions.
        """
        _LOGGER.info("Login")

        body = LOGIN_BODY.format(username=self.username,
                                 password=self.password)

        success, _ = self._make_request("ParentalControl:1", "Authenticate",
                                        None, body, False)

        self.logged_in = success

        return self.logged_in

    def get_attached_devices(self):
        """
        Return list of connected devices to the router.

        Returns None if error occurred.
        """
        _LOGGER.info("Get attached devices")

        success, response = self._make_request(SERVICE_DEVICE_INFO,
                                               "GetAttachDevice")

        if not success:
            return None

        success, node = _find_node(
            response,
            ".//GetAttachDeviceResponse/NewAttachDevice")
        if not success:
            return None

        # Netgear inserts a double-encoded value for "unknown" devices
        decoded = node.text.replace(UNKNOWN_DEVICE_ENCODED,
                                    UNKNOWN_DEVICE_DECODED)

        entries = decoded.split("@")
        devices = []

        # First element is the total device count
        if len(entries) > 1:
            entry_count = _convert(entries.pop(0), int)
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

            # Not all routers will report those
            signal = None
            link_type = None
            link_rate = None
            allow_or_block = None

            if len(info) >= 8:
                allow_or_block = info[7]
            if len(info) >= 7:
                link_type = info[4]
                link_rate = _convert(info[5], int)
                signal = _convert(info[6], int)

            if len(info) < 4:
                _LOGGER.warning("Unexpected entry: %s", info)
                continue

            ipv4, name, mac = info[1:4]

            devices.append(Device(signal, ipv4, name, mac,
                                  link_type, link_rate, allow_or_block,
                                  None, None, None, None))

        return devices

    def get_attached_devices_2(self):
        """
        Return list of connected devices to the router with details.

        This call is slower and probably heavier on the router load.

        Returns None if error occurred.
        """
        _LOGGER.info("Get attached devices 2")

        success, response = self._make_request(SERVICE_DEVICE_INFO,
                                               "GetAttachDevice2")
        if not success:
            return None

        success, devices_node = _find_node(
            response,
            ".//GetAttachDevice2Response/NewAttachDevice")
        if not success:
            return None

        xml_devices = devices_node.findall("Device")
        devices = []
        for d in xml_devices:
            ip = _xml_get(d, 'IP')
            name = _xml_get(d, 'Name')
            mac = _xml_get(d, 'MAC')
            signal = _convert(_xml_get(d, 'SignalStrength'), int)
            link_type = _xml_get(d, 'ConnectionType')
            link_rate = _xml_get(d, 'Linkspeed')
            allow_or_block = _xml_get(d, 'AllowOrBlock')
            device_type = _convert(_xml_get(d, 'DeviceType'), int)
            device_model = _xml_get(d, 'DeviceModel')
            ssid = _xml_get(d, 'SSID')
            conn_ap_mac = _xml_get(d, 'ConnAPMAC')
            devices.append(Device(signal, ip, name, mac, link_type, link_rate,
                                  allow_or_block, device_type, device_model,
                                  ssid, conn_ap_mac))

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

        success, response = self._make_request(SERVICE_DEVICE_CONFIG,
                                               "GetTrafficMeterStatistics")
        if not success:
            return None

        success, node = _find_node(
            response,
            ".//GetTrafficMeterStatisticsResponse")
        if not success:
            return None

        return {t.tag: parse_text(t.text) for t in node}

    def _make_request(self, service, method, params=None, body="",
                      try_login_after_failure=True):
        """Make an API request to the router."""
        # If we are not logged in, the request will fail for sure.
        if not self.logged_in and try_login_after_failure:
            if not self.login():
                return False, ""

        headers = _get_soap_header(service, method)

        if not body:
            if not params:
                params = ""
            if isinstance(params, dict):
                map = params
                params = ""
                for k in map:
                    params += "<" + k + ">" + map[k] + "</" + k + ">\n"

            body = CALL_BODY.format(service=SERVICE_PREFIX + service,
                                    method=method, params=params)

        message = SOAP_REQUEST.format(session_id=SESSION_ID, body=body)

        try:
            req = requests.post(self.soap_url, headers=headers,
                                data=message, timeout=10, verify=False)

            success = _is_valid_response(req)

            if not success and try_login_after_failure:
                self.login()

                req = requests.post(self.soap_url, headers=headers,
                                    data=message, timeout=10, verify=False)

                success = _is_valid_response(req)

            return success, req.text

        except requests.exceptions.RequestException:
            _LOGGER.exception("Error talking to API")

            # Maybe one day we will distinguish between
            # different errors..
            return False, ""


def autodetect_url():
    """
    Try to autodetect the base URL of the router SOAP service.

    Returns None if it can't be found.
    """
    for url in ["http://routerlogin.net:5000", "https://routerlogin.net",
                "http://routerlogin.net"]:
        try:
            r = requests.get(url + "/soap/server_sa/",
                             headers=_get_soap_header("Test:1", "test"),
                             verify=False)
            if r.status_code == 200:
                return url
        except:
            pass

    return None


def _find_node(response, xpath):
    it = ET.iterparse(StringIO(response))
    # strip all namespaces
    for _, el in it:
        if '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]
    node = it.root.find(xpath)
    if node is None:
        _LOGGER.error("Error finding node in response: %s", response)
        return False, None

    return True, node


def _xml_get(e, name):
    """
    Returns the value of the subnode "name" of element e.

    Returns None if the subnode doesn't exist
    """
    r = e.find(name)
    if r is not None:
        return r.text
    return None


def _get_soap_header(service, method):
    action = SERVICE_PREFIX + service + "#" + method
    return {"SOAPAction": action}


def _is_valid_response(resp):
    return (resp.status_code == 200 and
            "<ResponseCode>000</ResponseCode>" in resp.text)


def _convert(value, to_type, default=None):
    """Convert value to to_type, returns default if fails."""
    try:
        return default if value is None else to_type(value)
    except ValueError:
        # If value could not be converted
        return default

SERVICE_PREFIX = "urn:NETGEAR-ROUTER:service:"
SERVICE_DEVICE_INFO = "DeviceInfo:1"
SERVICE_DEVICE_CONFIG = "DeviceConfig:1"

REGEX_ATTACHED_DEVICES = r"<NewAttachDevice>(.*)</NewAttachDevice>"

# Until we know how to generate it, give the one we captured
SESSION_ID = "A7D88AE69687E58D9A00"

SOAP_REQUEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAPSDK1="http://www.w3.org/2001/XMLSchema"
  xmlns:SOAPSDK2="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:SOAPSDK3="http://schemas.xmlsoap.org/soap/encoding/"
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header>
<SessionID>{session_id}</SessionID>
</SOAP-ENV:Header>
{body}
</SOAP-ENV:Envelope>
"""

LOGIN_BODY = """<SOAP-ENV:Body>
<Authenticate>
  <NewUsername>{username}</NewUsername>
  <NewPassword>{password}</NewPassword>
</Authenticate>
</SOAP-ENV:Body>"""

CALL_BODY = """<SOAP-ENV:Body>
<M1:{method} xmlns:M1="{service}">
{params}</M1:{method}>
</SOAP-ENV:Body>"""

UNKNOWN_DEVICE_DECODED = '<unknown>'
UNKNOWN_DEVICE_ENCODED = '&lt;unknown&gt;'
