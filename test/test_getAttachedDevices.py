import unittest
from unittest import mock

# Import from the local version of pynetgear
from inspect import getsourcefile
import os.path as path, sys
current_dir = path.dirname(path.abspath(getsourcefile(lambda:0)))
netgear_dir = current_dir + '/../pynetgear'
sys.path.insert(0, netgear_dir)
from __init__ import Netgear, Device


class TestGetAttachedDevices(unittest.TestCase):
    def test_noSignalType(self):
        spy = NetgearSpy(RESPONSE_NO_SIGNAL_TYPE)
        mocked_netgear = mock.Mock(wraps=spy)

        result = spy.get_attached_devices()
        assert result == [
            Device(
                signal=None,
                ip="192.168.1.4",
                name="MACBOOK-PRO",
                mac="80:E6:50:13:2B:E0",
                type=None,
                link_rate=None,
                allow_or_block=None,
                device_type=None,
                device_model=None,
                ssid=None,
                conn_ap_mac=None,
            ),
            Device(
                signal=None,
                ip="192.168.1.18",
                name="RASPBERRYPI",
                mac="B8:27:EB:D9:05:E1",
                type=None,
                link_rate=None,
                allow_or_block=None,
                device_type=None,
                device_model=None,
                ssid=None,
                conn_ap_mac=None,
            ),
        ]

    def test_withSignalType(self):
        spy = NetgearSpy(RESPONSE_WITH_SIGNAL_TYPE)
        mocked_netgear = mock.Mock(wraps=spy)

        result = spy.get_attached_devices()
        assert result == [
            Device(
                signal=88,
                ip="192.168.1.2",
                name="android-ada682e3ff4d6b20",
                mac="10:68:3F:AA:AA:AA",
                type="wireless",
                link_rate=72,
                allow_or_block=None,
                device_type=None,
                device_model=None,
                ssid=None,
                conn_ap_mac=None,
            ),
            Device(
                signal=100,
                ip="192.168.1.3",
                name="odin",
                mac="C8:9C:DC:AA:AA:AA",
                type="wired",
                link_rate=None,
                allow_or_block=None,
                device_type=None,
                device_model=None,
                ssid=None,
                conn_ap_mac=None,
            ),
        ]

    def test_invalidResponse(self):
        spy = NetgearSpy(RESPONSE_INVALID)
        mocked_netgear = mock.Mock(wraps=spy)
        result = spy.get_attached_devices()
        assert result is None

    def test_responseMissingSplitChar(self):
        spy = NetgearSpy(RESPONSE_MISSGING_SPLIT_CHAR)
        mocked_netgear = mock.Mock(wraps=spy)
        result = spy.get_attached_devices()
        assert result == []

    def test_responseUnknownDevice(self):
        spy = NetgearSpy(RESONSE_UNKOWN_DEVICE)
        mocked_netgear = mock.Mock(wraps=spy)
        result = spy.get_attached_devices()
        assert result == [
            Device(
                signal=None,
                ip="192.168.1.2",
                name="<unknown>",
                mac="10:68:3F:AA:AA:AA",
                type=None,
                link_rate=None,
                allow_or_block=None,
                device_type=None,
                device_model=None,
                ssid=None,
                conn_ap_mac=None,
            )
        ]
    
    def test_double_unknown_response(self):
        spy = NetgearSpy(RESPONSE_DOUBLE_UNKNOWN)
        mocked_netgear = mock.Mock(wraps=spy)
        result = spy.get_attached_devices()
        assert result == [
            Device(
                signal=88,
                ip="<unknown>",
                name="<unknown>",
                mac="00:11:22:33:44:55",
                type="wireless",
                link_rate=84,
                allow_or_block="Allow",
                device_type=None,
                device_model=None,
                ssid=None,
                conn_ap_mac=None,
            )
        ]



class NetgearSpy(Netgear):
    def __init__(self, response):
        super().__init__
        self.response = response

    def _make_request(self, action, message, try_login_after_failure=True):
        result = True
        response = self.response
        return result, response


class MockResponse:
    def __init__(self, text):
        self.text = (
            """<?xml version="1.0" encoding="UTF-8"?>
            <SOAP-ENV:Envelope
            xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
            SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <SOAP-ENV:Body>
            <m:GetAttachDeviceResponse xmlns:m="urn:NETGEAR-ROUTER:service:DeviceInfo:1">"""
            + text
            + """
            </m:GetAttachDeviceResponse>
            <ResponseCode>000</ResponseCode>
            </SOAP-ENV:Body>
            </SOAP-ENV:Envelope>"""
        )


RESPONSE_NO_SIGNAL_TYPE = MockResponse(
    "<NewAttachDevice>\
2@1;192.168.1.4;MACBOOK-PRO;80:E6:50:13:2B:E0\
@3;192.168.1.18;RASPBERRYPI;B8:27:EB:D9:05:E1\
</NewAttachDevice>"
)

RESPONSE_WITH_SIGNAL_TYPE = MockResponse(
    "<NewAttachDevice>\
2@1;192.168.1.2;android-ada682e3ff4d6b20;10:68:3F:AA:AA:AA;wireless;72;88\
@2;192.168.1.3;odin;C8:9C:DC:AA:AA:AA;wired;;100\
</NewAttachDevice>"
)

RESPONSE_INVALID = MockResponse("INVALID")

RESPONSE_MISSGING_SPLIT_CHAR = MockResponse(
    "<NewAttachDevice>\
UNKNOWN#FORMATTING\
</NewAttachDevice>"
)

RESONSE_UNKOWN_DEVICE = MockResponse(
    "<NewAttachDevice>\
1@1;192.168.1.2;&lt;unknown&gt;;10:68:3F:AA:AA:AA\
</NewAttachDevice>"
)

RESPONSE_DOUBLE_UNKNOWN = MockResponse(
    "<NewAttachDevice>\
@1;&lt;unknown&gt;&lt;unknown&gt;;00:11:22:33:44:55;wireless;84;88;Allow\
</NewAttachDevice>"
)

if __name__ == "__main__":
    unittest.main()
