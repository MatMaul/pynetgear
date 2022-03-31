"""Module to communicate with Netgear routers using the SOAP v2 API."""
from __future__ import print_function

from io import StringIO
from collections import namedtuple
import logging
import xml.etree.ElementTree as ET
from datetime import timedelta
import re
import sys

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)

# define regex to filter invalid XML codes
# cf https://stackoverflow.com/questions/1707890/fast-way-to-filter-illegal-xml-unicode-chars-in-python
if sys.version_info[0] == 3:
    unichr = chr
_illegal_unichrs = [(0x00, 0x08), (0x0B, 0x0C), (0x0E, 0x1F),
                    (0x7F, 0x84), (0x86, 0x9F),
                    (0xFDD0, 0xFDDF), (0xFFFE, 0xFFFF)]
if sys.maxunicode >= 0x10000:  # not narrow build
    _illegal_unichrs.extend([(0x1FFFE, 0x1FFFF), (0x2FFFE, 0x2FFFF),
                             (0x3FFFE, 0x3FFFF), (0x4FFFE, 0x4FFFF),
                             (0x5FFFE, 0x5FFFF), (0x6FFFE, 0x6FFFF),
                             (0x7FFFE, 0x7FFFF), (0x8FFFE, 0x8FFFF),
                             (0x9FFFE, 0x9FFFF), (0xAFFFE, 0xAFFFF),
                             (0xBFFFE, 0xBFFFF), (0xCFFFE, 0xCFFFF),
                             (0xDFFFE, 0xDFFFF), (0xEFFFE, 0xEFFFF),
                             (0xFFFFE, 0xFFFFF), (0x10FFFE, 0x10FFFF)])

_illegal_ranges = ["%s-%s" % (unichr(low), unichr(high))
                   for (low, high) in _illegal_unichrs]
_illegal_xml_chars_RE = re.compile(u'[%s]' % u''.join(_illegal_ranges))


DEFAULT_HOST = 'routerlogin.net'
DEFAULT_USER = 'admin'
DEFAULT_PORT = 5000
ALL_PORTS = [(5555, True), (443, True), (5000, False), (80, False)]
_LOGGER = logging.getLogger(__name__)


BLOCK = "Block"
ALLOW = "Allow"

Device = namedtuple(
    "Device", [
        "name",
        "ip",
        "mac",
        "type",
        "signal",
        "link_rate",
        "allow_or_block",
        "device_type",
        "device_model",
        "ssid",
        "conn_ap_mac"
    ]
)


class Netgear(object):
    """Represents a session to a Netgear Router."""

    def __init__(
        self,
        password=None,
        host=None,
        user=None,
        port=None,
        ssl=False,
        url=None,
        force_login_v1=False,
        force_login_v2=False,
    ):
        """Initialize a Netgear session."""
        if not url and not host and not port:
            url = autodetect_url()

        if not host:
            host = DEFAULT_HOST
        if not port:
            port = DEFAULT_PORT
        if not user:
            user = DEFAULT_USER

        self.username = user
        self.password = password
        self.url = url
        self.host = host
        self.port = port
        self.ssl = ssl
        self.force_login_v1 = force_login_v1
        self.force_login_v2 = force_login_v2
        self.cookie = None
        self.config_started = False
        self._logging_in = False
        self._login_version = 2

        self._info = None

    @property
    def soap_url(self):
        """SOAP url to connect to the router."""
        if self.url:
            return self.url + "/soap/server_sa/"

        scheme = "https" if self.ssl else "http"
        return "{}://{}:{}/soap/server_sa/".format(
            scheme, self.host, self.port)

    def login_try_port(self):
        # first try the currently configured port-ssl combination
        current_port = (self.port, self.ssl)
        if self.login():
            return True

        ports = ALL_PORTS.copy()
        if current_port in ports:
            ports.remove(current_port)

        for port in ports:
            self.port = port[0]
            self.ssl = port[1]
            if self.login():
                _LOGGER.info("Login succeeded using non default port "
                             "'%i' and ssl '%r'.", self.port, self.ssl)
                return True

        # reset original port-ssl
        self.port = current_port[0]
        self.ssl = current_port[1]
        _LOGGER.error("login using all known port-ssl combinations failed.")
        return False

    def login(self):
        """
        Login to the router.

        Will be called automatically by other actions.
        """
        if self._logging_in:
            _LOGGER.debug("Login re-attempt within the login, ignoring.")
            return False
        self._logging_in = True

        # cookie is also used to track if at least
        # one login attempt has been made for v1
        self.cookie = None

        # if a force option is given always start with that method
        if self.force_login_v1:
            self._login_version = 1
        if self.force_login_v2:
            self._login_version = 2

        login_methods = [self.login_v1, self.login_v2]
        for idx in range(0, len(login_methods)):
            login_version = (idx + self._login_version) % len(login_methods)
            login_method = login_methods[login_version-1]
            if login_method():
                # login succeeded, next time start with this login method
                self._logging_in = False
                self._login_version = login_version
                return True

        # login failed, next time start trying with the other login method
        self._logging_in = False
        self._login_version = self._login_version + 1
        return False

    def login_v2(self):
        _LOGGER.debug("Login v2, port '%i', ssl, '%r'", self.port, self.ssl)

        success, response = self._make_request(
            SERVICE_DEVICE_CONFIG,
            "SOAPLogin",
            {
                "Username": self.username,
                "Password": self.password
            },
            None,
            False
        )

        if not success:
            return False

        if 'Set-Cookie' in response.headers:
            self.cookie = response.headers['Set-Cookie']
        else:
            _LOGGER.error("Login v2 ok but no cookie...")
            _LOGGER.debug(response.headers)
            return False

        return True

    def login_v1(self):
        _LOGGER.debug("Login v1, port '%i', ssl, '%r'", self.port, self.ssl)

        body = LOGIN_V1_BODY.format(username=self.username,
                                    password=self.password)

        success, _ = self._make_request(
            "ParentalControl:1",
            "Authenticate",
            None,
            body,
            False
        )

        self.cookie = success

        # check login succes with info call
        if self.get_info(use_cache=False) is None:
            return False

        return True

    def get_info(self, use_cache=True):
        """
        Return router informations, like:
        - ModelName
        - DeviceName
        - SerialNumber
        - Firmwareversion
        - FirewallVersion
        - Hardwareversion
        - FirmwareLastUpdate
        - FirmwareLastChecked

        Returns None if error occurred.
        """
        _LOGGER.debug("Get Info")

        if self._info is not None and use_cache:
            _LOGGER.debug("Info from cache.")
            return self._info

        success, response = self._make_request(
            SERVICE_DEVICE_INFO,
            "GetInfo"
        )
        if not success:
            return None

        success, node = _find_node(
            response.text,
            ".//GetInfoResponse")
        if not success:
            return None

        self._info = {t.tag: t.text for t in node}

        return self._info

    def get_attached_devices(self):
        """
        Return list of connected devices to the router.

        Returns None if error occurred.
        """
        _LOGGER.debug("Get attached devices")

        success, response = self._make_request(
            SERVICE_DEVICE_INFO,
            "GetAttachDevice"
        )

        if not success:
            _LOGGER.error("Get attached devices failed")
            return None

        success, node = _find_node(
            response.text,
            ".//GetAttachDeviceResponse/NewAttachDevice")
        if not success:
            return None

        devices = []

        # Netgear inserts a double-encoded value for "unknown" devices
        decoded = node.text.strip().replace(UNKNOWN_DEVICE_ENCODED,
                                            UNKNOWN_DEVICE_DECODED)

        if not decoded or decoded == "0":
            _LOGGER.info("Can't parse attached devices string")
            return devices

        entries = decoded.split("@")

        # First element is the total device count
        entry_count = None
        if len(entries) > 1:
            entry_count = _convert(entries.pop(0), int)

        if entry_count is not None and entry_count != len(entries):
            _LOGGER.info(
                "Number of devices should be: %d but is: %d",
                entry_count,
                len(entries)
            )

        for entry in entries:
            info = entry.split(";")

            if len(info) == 0:
                continue

            # Not all routers will report those
            signal = None
            link_type = None
            link_rate = None
            allow_or_block = None
            mac = None
            name = None

            if len(info) >= 8:
                allow_or_block = info[7]
            if len(info) >= 7:
                link_type = info[4]
                link_rate = _convert(info[5], int)
                signal = _convert(info[6], int)
            if len(info) >= 4:
                mac = info[3]
            if len(info) >= 3:
                name = info[2]

            if len(info) < 2:
                _LOGGER.warning("Unexpected entry: %s", info)
                continue

            ipv4 = info[1]

            devices.append(Device(name, ipv4, mac,
                                  link_type, signal, link_rate, allow_or_block,
                                  None, None, None, None))

        return devices

    def get_attached_devices_2(self):
        """
        Return list of connected devices to the router with details.

        This call is slower and probably heavier on the router load.

        Returns None if error occurred.
        """
        _LOGGER.debug("Get attached devices 2")

        success, response = self._make_request(
            SERVICE_DEVICE_INFO,
            "GetAttachDevice2"
        )
        if not success:
            return None

        success, devices_node = _find_node(
            response.text,
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
            devices.append(
                Device(
                    name,
                    ip,
                    mac,
                    link_type,
                    signal,
                    link_rate,
                    allow_or_block,
                    device_type,
                    device_model,
                    ssid,
                    conn_ap_mac
                )
            )

        return devices

    def get_traffic_meter(self):
        """
        Return dict of traffic meter stats.

        Returns None if error occurred.
        """
        _LOGGER.debug("Get traffic meter")

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
            SERVICE_DEVICE_CONFIG,
            "GetTrafficMeterStatistics"
        )
        if not success:
            return None

        success, node = _find_node(
            response.text,
            ".//GetTrafficMeterStatisticsResponse")
        if not success:
            return None

        return {t.tag: parse_text(t.text) for t in node}

    def config_start(self):
        """
        Start a configuration session.
        For managing router admin functionality (ie allowing/blocking devices)
        """
        _LOGGER.debug("Config start")

        success, _ = self._make_request(
            SERVICE_DEVICE_CONFIG,
            "ConfigurationStarted",
            {
                "NewSessionID": SESSION_ID
            }
        )

        self.config_started = success
        return success

    def config_finish(self):
        """
        End of a configuration session.
        Tells the router we're done managing admin functionality.
        """
        _LOGGER.debug("Config finish")
        if not self.config_started:
            return True

        success, _ = self._make_request(
            SERVICE_DEVICE_CONFIG,
            "ConfigurationFinished",
            {
                "NewStatus": "ChangesApplied"
            }
        )

        self.config_started = not success
        return success

    def allow_block_device(self, mac_addr, device_status=BLOCK):
        """
        Allow or Block a device via its Mac Address.
        Pass in the mac address for the device that you want to set. Pass in the
        device_status you wish to set the device to: Allow (allow device to access the
        network) or Block (block the device from accessing the network).
        """
        _LOGGER.debug("Allow block device")
        if self.config_started:
            _LOGGER.error("Inconsistant configuration state, configuration already started")
            if not self.config_finish():
                return False

        if not self.config_start():
            _LOGGER.error("Could not start configuration")
            return False

        success, _ = self._make_request(
            SERVICE_DEVICE_CONFIG,
            "SetBlockDeviceByMAC",
            {
                "NewAllowOrBlock": device_status,
                "NewMACAddress": mac_addr
            }
        )

        if not success:
            _LOGGER.error("Could not successfully call allow/block device")
            return False

        if not self.config_finish():
            _LOGGER.error("Inconsistant configuration state, configuration already finished")
            return False

        return True

    def _get_headers(self, service, method, need_auth=True):
        headers = _get_soap_headers(service, method)
        # if the stored cookie is not a str then we are
        # probably using the old login method
        if need_auth and isinstance(self.cookie, str):
            headers["Cookie"] = self.cookie
        return headers

    def reboot(self):
        _LOGGER.debug("reboot")
        if self.config_started:
            _LOGGER.error("Inconsistant configuration state, configuration already started")
            if not self.config_finish():
                return False

        if not self.config_start():
            _LOGGER.error("Could not start configuration")
            return False

        success, _ = self._make_request(
            SERVICE_DEVICE_CONFIG,
            "Reboot",
            )

        if not success:
            _LOGGER.error("Could not successfully call reboot")
            return False

        self.config_started = False

        return True

    def _post_request(self, headers, message):
        """Post the API request to the router."""
        return requests.post(
            self.soap_url, headers=headers, data=message,
            timeout=30, verify=False
        )

    def _make_request(
        self,
        service,
        method,
        params=None,
        body="",
        need_auth=True
    ):
        """Make an API request to the router."""
        # If we have no cookie (v2) or never called login before (v1)
        # and we need auth, the request will fail for sure.
        if need_auth and not self.cookie:
            if not self.login():
                return False, None

        headers = self._get_headers(service, method, need_auth)

        if not body:
            if not params:
                params = ""
            if isinstance(params, dict):
                _map = params
                params = ""
                for k in _map:
                    params += "<" + k + ">" + _map[k] + "</" + k + ">\n"

            body = CALL_BODY.format(service=SERVICE_PREFIX + service,
                                    method=method, params=params)

        message = SOAP_REQUEST.format(session_id=SESSION_ID, body=body)

        try:
            try:
                response = self._post_request(headers, message)
            except requests.exceptions.SSLError:
                _LOGGER.debug("SSL error, thread as unauthorized response "
                              "and try again after re-login")
                response = requests.Response()
                response.status_code = 401

            if need_auth and _is_unauthorized_response(response):
                # let's discard the cookie because it probably expired (v2)
                # or the IP-bound session expired (v1)
                self.cookie = None

                _LOGGER.debug("Unauthorized response, "
                              "let's login and retry...")
                if not self.login():
                    _LOGGER.error("Unauthorized response, re-login failed")
                    return False, response

                # reset headers with new cookie first and re-try
                headers = self._get_headers(service, method, need_auth)
                response = self._post_request(headers, message)

            success = _is_valid_response(response)
            if not success and not self._logging_in:
                if _is_unauthorized_response(response):
                    _LOGGER.error("Unauthorized response, "
                                  "after seemingly successful re-login")
                elif _is_service_unavailable_response(response):
                    # try the request one more time
                    response = self._post_request(headers, message)
                    success = _is_valid_response(response)
                    if not success:
                        _LOGGER.error("503 Service Unavailable after retry, "
                                      "the API may be overloaded.")
                else:
                    _LOGGER.error("Invalid response: %s\n%s\n%s",
                                  response.status_code, str(response.headers),
                                  response.text)

            return success, response

        except requests.exceptions.RequestException:
            _LOGGER.exception("Error talking to API")
            self.cookie = None

            # Maybe one day we will distinguish between
            # different errors..
            return False, None


def autodetect_url():
    """
    Try to autodetect the base URL of the router SOAP service.

    Returns None if it can't be found.
    """
    DETECTABLE_URLS = [
        "http://routerlogin.net",
        "http://routerlogin.net:5000",
        "https://routerlogin.net",
    ]
    for url in DETECTABLE_URLS:
        try:
            resp = requests.get(
                url + "/soap/server_sa/",
                headers=_get_soap_headers("Test:1", "test"),
                verify=False,
                timeout=1
            )
            if resp.status_code == 200:
                return url
        except requests.exceptions.RequestException:
            pass

    return None


def _find_node(text, xpath):
    text = _illegal_xml_chars_RE.sub('', text)
    it = ET.iterparse(StringIO(text))
    # strip all namespaces
    for _, el in it:
        if '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]
    node = it.root.find(xpath)
    if node is None:
        _LOGGER.error("Error finding node in XML response")
        _LOGGER.debug(text)
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


def _get_soap_headers(service, method):
    action = SERVICE_PREFIX + service + "#" + method
    return {
        "SOAPAction":    action,
        "Cache-Control": "no-cache",
        "User-Agent":    "pynetgear",
        "Content-Type":  "multipart/form-data"
    }


def _is_valid_response(resp):
    return (resp.status_code == 200 and
            ("<ResponseCode>0000</" in resp.text or
             "<ResponseCode>000</" in resp.text))


def _is_unauthorized_response(resp):
    return (resp.status_code == 401 or
            "<ResponseCode>401</ResponseCode>" in resp.text)


def _is_service_unavailable_response(resp):
    return (resp.status_code == 503 or
            "<ResponseCode>503</ResponseCode>" in resp.text)


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

LOGIN_V1_BODY = """<SOAP-ENV:Body>
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
