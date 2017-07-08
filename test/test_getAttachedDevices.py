import unittest
from unittest import mock
from pynetgear import Netgear, Device


class TestGetAttachedDevices(unittest.TestCase):

    def test_noSignalType(self):
        spy = NetgearSpy(RESPONSE_NO_SIGNAL_TYPE)
        mocked_netgear = mock.Mock(wraps=spy)

        result = spy.get_attached_devices()
        assert result == [Device(signal=100, ip='192.168.1.4',
                                 name='MACBOOK-PRO', mac='80:E6:50:13:2B:E0',
                                 type=None, link_rate=0),
                          Device(signal=100, ip='192.168.1.18',
                                 name='RASPBERRYPI', mac='B8:27:EB:D9:05:E1',
                                 type=None, link_rate=0)]

    def test_withSignalType(self):
        spy = NetgearSpy(RESPONSE_WITH_SIGNAL_TYPE)
        mocked_netgear = mock.Mock(wraps=spy)

        result = spy.get_attached_devices()
        assert result == [Device(signal=88, ip='192.168.1.2',
                                 name='android-ada682e3ff4d6b20',
                                 mac='10:68:3F:AA:AA:AA',
                                 type='wireless', link_rate=72),
                          Device(signal=100, ip='192.168.1.3', name='odin',
                                 mac='C8:9C:DC:AA:AA:AA', type='wired',
                                 link_rate=None)]

    def test_invalidResponse(self):
        spy = NetgearSpy(RESPONSE_INVALID)
        mocked_netgear = mock.Mock(wraps=spy)
        result = spy.get_attached_devices()
        assert result is None

    def test_responseMissingSplitChar(self):
        spy = NetgearSpy(RESPONSE_MISSGING_SPLIT_CHAR)
        mocked_netgear = mock.Mock(wraps=spy)
        result = spy.get_attached_devices()
        assert result is None

    def test_responseUnknownDevice(self):
        spy = NetgearSpy(RESONSE_UNKOWN_DEVICE)
        mocked_netgear = mock.Mock(wraps=spy)
        result = spy.get_attached_devices()
        assert result == [Device(signal=100, ip='192.168.1.2',
                                 name='<unknown>',
                                 mac='10:68:3F:AA:AA:AA',
                                 type=None, link_rate=0)]


if __name__ == '__main__':
    unittest.main()


class NetgearSpy(Netgear):
    def __init__(self, response):
        super().__init__
        self.response = response

    def _make_request(self, action, message, try_login_after_failure=True):
        result = True
        response = self.response
        return result, response


RESPONSE_NO_SIGNAL_TYPE = "<NewAttachDevice>\
2@1;192.168.1.4;MACBOOK-PRO;80:E6:50:13:2B:E0\
@3;192.168.1.18;RASPBERRYPI;B8:27:EB:D9:05:E1\
</NewAttachDevice>"

RESPONSE_WITH_SIGNAL_TYPE = "<NewAttachDevice>\
2@1;192.168.1.2;android-ada682e3ff4d6b20;10:68:3F:AA:AA:AA;wireless;72;88\
@2;192.168.1.3;odin;C8:9C:DC:AA:AA:AA;wired;;100\
</NewAttachDevice>"

RESPONSE_INVALID = "INVALID"

RESPONSE_MISSGING_SPLIT_CHAR = "<NewAttachDevice>\
UNKNOWN#FORMATTING\
</NewAttachDevice>"

RESONSE_UNKOWN_DEVICE = "<NewAttachDevice>\
1@1;192.168.1.2;&lt;unknown&gt;;10:68:3F:AA:AA:AA\
</NewAttachDevice>"
