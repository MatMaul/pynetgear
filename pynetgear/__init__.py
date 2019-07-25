# encoding: utf-8
"""Module to communicate with Netgear routers using the SOAP v2 API."""
from __future__ import print_function

from collections import namedtuple
import logging
import requests

from . import const as c
from . import helpers as h

_LOGGER = logging.getLogger(__name__)

Device = namedtuple(
    "Device", ["name", "ip", "mac", "type", "signal", "link_rate",
               "allow_or_block", "device_type", "device_model",
               "ssid", "conn_ap_mac"])


class Netgear():
    """Represents a session to a Netgear Router."""

    def __init__(self, password=None, host=None, user=None, port=None,  # noqa
                 ssl=False, url=None, force_login_v2=False):
        """Initialize a Netgear session."""
        if not url and not host and not port:
            url = h.autodetect_url()

        if url:
            self.soap_url = url + "/soap/server_sa/"
        else:
            if not host:
                host = c.DEFAULT_HOST
            if not port:
                port = c.DEFAULT_PORT
            scheme = "https" if ssl else "http"
            self.soap_url = "{}://{}:{}/soap/server_sa/".format(scheme,
                                                                host, port)

        if not user:
            user = c.DEFAULT_USER

        self.username = user
        self.password = password
        self.port = port
        self.force_login_v2 = force_login_v2
        self.cookie = None
        self.config_started = False

    ##########################################################################
    # HELPERS
    ##########################################################################
    def login(self):
        """
        Login to the router.

        Will be called automatically by other actions.
        """
        if not self.force_login_v2:
            v1_result = self.login_v1()
            if v1_result:
                return v1_result

        return self.login_v2()

    def _get_headers(self, service, method, need_auth=True):
        headers = h.get_soap_headers(service, method)
        # if the stored cookie is not a str then we are
        # probably using the old login method
        if need_auth and isinstance(self.cookie, str):
            headers["Cookie"] = self.cookie
        return headers

    def _make_request(self, service, method, params=None, body="",  # noqa
                      need_auth=True):
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
            response = requests.post(self.soap_url, headers=headers,
                                     data=message, timeout=30, verify=False)

            if need_auth and h.is_unauthorized_response(response):
                # let's discard the cookie because it probably expired (v2)
                # or the IP-bound (?) session expired (v1)
                self.cookie = None

                _LOGGER.warning(
                    "Unauthorized response, let's login and retry..."
                    )
                if self.login():
                    # reset headers with new cookie first
                    headers = self._get_headers(service, method, need_auth)
                    response = requests.post(
                        self.soap_url, headers=headers,
                        data=message, timeout=30, verify=False
                        )

            success = h.is_valid_response(response)

            if not success:
                _LOGGER.error("Invalid response")
                _LOGGER.debug(
                    "%s\n%s\n%s", response.status_code,
                    str(response.headers), response.text
                    )

            return success, response

        except requests.exceptions.RequestException:
            _LOGGER.exception("Error talking to API")

            # Maybe one day we will distinguish between
            # different errors..
            return False, None

    ##########################################################################
    # SERVICE_DEVICE_CONFIG
    ##########################################################################
    def login_v2(self):
        """Attempt login."""
        _LOGGER.debug("Login v2")
        self.cookie = None

        success, response = self._make_request(
            c.SERVICE_DEVICE_CONFIG, c.LOGIN,
            {"Username": self.username, "Password": self.password},
            None, False
            )

        if not success:
            return None

        if 'Set-Cookie' in response.headers:
            self.cookie = response.headers['Set-Cookie']
        else:
            _LOGGER.error("Login v2 ok but no cookie...")
            _LOGGER.debug(response.headers)

        return self.cookie

    def config_start(self):
        """
        Start a configuration session.

        For managing router admin functionality (ie allowing/blocking devices)
        """
        _LOGGER.info("Config start")

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG, c.CONFIGURATION_STARTED,
            {"NewSessionID": c.SESSION_ID}
            )

        self.config_started = success
        return success

    def config_finish(self):
        """
        End of a configuration session.

        Tells the router we're done managing admin functionality.
        """
        _LOGGER.info("Config finish")
        if not self.config_started:
            return True

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG, c.CONFIGURATION_FINISHED,
            {"NewStatus": "ChangesApplied"}
            )

        self.config_started = not success
        return success

    def allow_block_device(self, mac_addr,
                           device_status=c.BLOCK):
        """
        Allow or Block a device via its Mac Address.

        Pass in the mac address for the device that you want to set.
        Pass in the device_status you wish to set the device to: Allow
        (allow device to access the network) or Block (block the device
        from accessing the network).
        """
        _LOGGER.info("Allow block device")
        if self.config_started:
            _LOGGER.error(
                "Inconsistant configuration state, "
                "configuration already started"
                )
            return False

        if not self.config_start():
            _LOGGER.error("Could not start configuration")
            return False

        success, _ = self._make_request(
            c.SERVICE_DEVICE_CONFIG, c.SET_BLOCK_DEVICE_BY_MAC,
            {"NewAllowOrBlock": device_status, "NewMACAddress": mac_addr})

        if not success:
            _LOGGER.error("Could not successfully call allow/block device")
            return False

        if not self.config_finish():
            _LOGGER.error(
                "Inconsistant configuration state, "
                "configuration already finished"
                )
            return False

        return True

    def get_traffic_meter(self):
        """
        Return dict of traffic meter stats.

        Returns None if error occurred.
        """
        _LOGGER.info("Get traffic meter")

        success, response = self._make_request(c.SERVICE_DEVICE_CONFIG,
                                               c.GET_TRAFFIC_METER_STATISTICS)
        if not success:
            return None

        success, node = h.find_node(
            response.text,
            f".//{c.GET_TRAFFIC_METER_STATISTICS}Response")
        if not success:
            return None

        return {t.tag: h.parse_text(t.text) for t in node}

    ##########################################################################
    # SERVICE_PARENTAL_CONTROL
    ##########################################################################
    def login_v1(self):
        """Attempt login."""
        _LOGGER.debug("Login v1")

        body = c.LOGIN_V1_BODY.format(
            username=self.username, password=self.password
            )

        success, _ = self._make_request(
            c.SERVICE_PARENTAL_CONTROL, c.LOGIN_OLD, None, body, False
            )

        self.cookie = success

        return success

    ##########################################################################
    # SERVICE_DEVICE_INFO
    ##########################################################################
    def get_attached_devices(self):  # noqa
        """
        Return list of connected devices to the router.

        Returns None if error occurred.
        """
        _LOGGER.info("Get attached devices")

        success, response = self._make_request(c.SERVICE_DEVICE_INFO,
                                               c.GET_ATTACHED_DEVICES)

        if not success:
            _LOGGER.error("Get attached devices failed")
            return None

        success, node = h.find_node(
            response.text,
            f".//{c.GET_ATTACHED_DEVICES}Response/NewAttachDevice")
        if not success:
            return None

        devices = []

        # Netgear inserts a double-encoded value for "unknown" devices
        decoded = node.text.strip().replace(c.UNKNOWN_DEVICE_ENCODED,
                                            c.UNKNOWN_DEVICE_DECODED)

        if not decoded or decoded == "0":
            _LOGGER.error("Can't parse attached devices string")
            _LOGGER.debug(node.text.strip())
            return devices

        entries = decoded.split("@")

        # First element is the total device count
        entry_count = None
        if len(entries) > 1:
            entry_count = h.convert(entries.pop(0), int)

        if entry_count is not None and entry_count != len(entries):
            _LOGGER.info(
                """Number of devices should \
                 be: %d but is: %d""", entry_count, len(entries))

        for entry in entries:
            info = entry.split(";")

            if not info:
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
                link_rate = h.convert(info[5], int)
                signal = h.convert(info[6], int)

            if len(info) < 4:
                _LOGGER.warning("Unexpected entry: %s", info)
                continue

            ipv4, name, mac = info[1:4]

            devices.append(Device(name, ipv4, mac,
                                  link_type, signal, link_rate, allow_or_block,
                                  None, None, None, None))

        return devices

    def get_attached_devices_2(self):  # noqa
        """
        Return list of connected devices to the router with details.

        This call is slower and probably heavier on the router load.

        Returns None if error occurred.
        """
        _LOGGER.info("Get attached devices 2")

        success, response = self._make_request(c.SERVICE_DEVICE_INFO,
                                               c.GET_ATTACHED_DEVICES_2)
        if not success:
            return None

        success, devices_node = h.find_node(
            response.text,
            f".//{c.GET_ATTACHED_DEVICES_2}Response/NewAttachDevice")
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
            devices.append(Device(name, ip, mac, link_type, signal, link_rate,
                                  allow_or_block, device_type, device_model,
                                  ssid, conn_ap_mac))

        return devices

    ##########################################################################
    # SERVICE_ADVANCED_QOS
    ##########################################################################

    ##########################################################################
    # SERVICE_WLAN_CONFIGURATION
    ##########################################################################
