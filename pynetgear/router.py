"""Module to communicate with Netgear routers using the SOAP v2 API."""
from __future__ import print_function

from collections import namedtuple
import logging
from datetime import timedelta

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from . import const as c
from . import helpers as h

_LOGGER = logging.getLogger(__name__)

disable_warnings(InsecureRequestWarning)


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
            url = h.autodetect_url()

        if not host:
            host = c.DEFAULT_HOST
        if not port:
            port = c.DEFAULT_PORT
        if not user:
            user = c.DEFAULT_USER

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

    def _get_headers(self, service, method, need_auth=True):
        headers = h.get_soap_headers(service, method)
        # if the stored cookie is not a str then we are
        # probably using the old login method
        if need_auth and isinstance(self.cookie, str):
            headers["Cookie"] = self.cookie
        return headers

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

            body = c.CALL_BODY.format(service=c.SERVICE_PREFIX + service,
                                    method=method, params=params)

        message = c.SOAP_REQUEST.format(session_id=c.SESSION_ID, body=body)

        try:
            try:
                response = self._post_request(headers, message)
            except requests.exceptions.SSLError:
                _LOGGER.debug("SSL error, thread as unauthorized response "
                              "and try again after re-login")
                response = requests.Response()
                response.status_code = 401

            if need_auth and h.is_unauthorized_response(response):
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

            success = h.is_valid_response(response)
            if not success and not self._logging_in:
                if h.is_unauthorized_response(response):
                    _LOGGER.error("Unauthorized response, "
                                  "after seemingly successful re-login")
                elif h.is_service_unavailable_response(response):
                    # try the request one more time
                    response = self._post_request(headers, message)
                    success = h.is_valid_response(response)
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

    def config_start(self):
        """
        Start a configuration session.
        For managing router admin functionality (ie allowing/blocking devices)
        """
        _LOGGER.debug("Config start")

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG,
            c.CONFIGURATION_STARTED,
            {
                "NewSessionID": c.SESSION_ID
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
            c.SERVICE_DEVICE_CONFIG,
            c.CONFIGURATION_FINISHED,
            {
                "NewStatus": "ChangesApplied"
            }
        )

        self.config_started = not success
        return success

    def _get(self, service, method, parseNode=None, parse_text=lambda text: text):
        """Get information using a service and method from the router."""
        if parseNode is None:
            parseNode = f".//{method}Response",

        _LOGGER.debug("Call %s", method)
        success, response = self._make_request(
            service,
            method
        )
        if not success:
            _LOGGER.debug("Could not successfully get %s", method)
            return None

        success, node = h.find_node(
            response.text,
            parseNode
        )
        if not success:
            _LOGGER.debug("Could not parse response for %s", method)
            return None

        return {t.tag: parse_text(t.text) for t in node}

    def _set(self, service, method, params=None):
        """Set router parameters using a service, method and params."""
        _LOGGER.debug("Call %s", method)
        if self.config_started:
            _LOGGER.error("Inconsistant configuration state, configuration already started")
            if not self.config_finish():
                return False

        if not self.config_start():
            _LOGGER.error("Could not start configuration")
            return False

        success, _ = self._make_request(service, method, params)

        if not success:
            _LOGGER.error("Could not successfully call '%s' with params '%s'", method, params)
            return False

        if method == c.REBOOT:
            self.config_started = False
            return True

        if not self.config_finish():
            _LOGGER.error("Inconsistant configuration state, configuration already finished")
            return False

        return True

    def login_try_port(self):
        # first try the currently configured port-ssl combination
        current_port = (self.port, self.ssl)
        if self.login():
            return True

        ports = c.ALL_PORTS.copy()
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
            c.SERVICE_DEVICE_CONFIG,
            c.LOGIN,
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

        body = c.LOGIN_V1_BODY.format(username=self.username,
                                    password=self.password)

        success, _ = self._make_request(
            c.SERVICE_PARENTAL_CONTROL,
            c.LOGIN_OLD,
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
        if self._info is not None and use_cache:
            _LOGGER.debug("Info from cache.")
            return self._info

        response = self._get(
            c.SERVICE_DEVICE_INFO,
            "GetInfo",
        )
        if response is None:
            return None

        self._info = response
        return self._info

    def get_attached_devices(self):
        """
        Return list of connected devices to the router.

        Returns None if error occurred.
        """
        _LOGGER.debug("Get attached devices")

        success, response = self._make_request(
            c.SERVICE_DEVICE_INFO,
            c.GET_ATTACHED_DEVICES
        )

        if not success:
            _LOGGER.error("Get attached devices failed")
            return None

        success, node = h.find_node(
            response.text,
            ".//GetAttachDeviceResponse/NewAttachDevice")
        if not success:
            return None

        devices = []

        # Netgear inserts a double-encoded value for "unknown" devices
        decoded = node.text.strip().replace(c.UNKNOWN_DEVICE_ENCODED,
                                            c.UNKNOWN_DEVICE_DECODED)

        if not decoded or decoded == "0":
            _LOGGER.info("Can't parse attached devices string")
            return devices

        entries = decoded.split("@")

        # First element is the total device count
        entry_count = None
        if len(entries) > 1:
            entry_count = h.convert(entries.pop(0), int)

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
                link_rate = h.convert(info[5], int)
                signal = h.convert(info[6], int)
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
            c.SERVICE_DEVICE_INFO,
            c.GET_ATTACHED_DEVICES_2
        )
        if not success:
            return None

        success, devices_node = h.find_node(
            response.text,
            ".//GetAttachDevice2Response/NewAttachDevice")
        if not success:
            return None

        xml_devices = devices_node.findall("Device")
        devices = []
        for d in xml_devices:
            ip = h.xml_get(d, 'IP')
            name = h.xml_get(d, 'Name')
            mac = h.xml_get(d, 'MAC')
            signal = h.convert(h.xml_get(d, 'SignalStrength'), int)
            link_type = h.xml_get(d, 'ConnectionType')
            link_rate = h.xml_get(d, 'Linkspeed')
            allow_or_block = h.xml_get(d, 'AllowOrBlock')
            device_type = h.convert(h.xml_get(d, 'DeviceType'), int)
            device_model = h.xml_get(d, 'DeviceModel')
            ssid = h.xml_get(d, 'SSID')
            conn_ap_mac = h.xml_get(d, 'ConnAPMAC')
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
        def parse_text(text):
            """
                there are three kinds of values in the returned data
                This function parses the different values and returns
                (total, avg), timedelta or a plain float
            """
            def tofloats(lst): return (float(t) for t in lst)
            try:
                text = text.replace(',', '')  # 25,350.10 MB
                if "--" in text:
                    return None
                if "/" in text:  # "6.19/0.88" total/avg
                    return tuple(tofloats(text.split('/')))
                if ":" in text:  # 11:14 hr:mn
                    hour, mins = tofloats(text.split(':'))
                    return timedelta(hours=hour, minutes=mins)
                return float(text)
            except ValueError:
                _LOGGER.error("Error parsing traffic meter stats: %s", text)
                return None

        return self._get(
            c.SERVICE_DEVICE_CONFIG,
            "GetTrafficMeterStatistics",
            parse_text = parse_text
        )

    def allow_block_device(self, mac_addr, device_status=c.BLOCK):
        """
        Allow or Block a device via its Mac Address.
        Pass in the mac address for the device that you want to set. Pass in the
        device_status you wish to set the device to: Allow (allow device to access the
        network) or Block (block the device from accessing the network).
        """
        return self._set(
            c.SERVICE_DEVICE_CONFIG,
            "SetBlockDeviceByMAC",
            {
                "NewAllowOrBlock": device_status,
                "NewMACAddress": mac_addr
            }
        )

    def reboot(self):
        return self._set(c.SERVICE_DEVICE_CONFIG, c.REBOOT)
