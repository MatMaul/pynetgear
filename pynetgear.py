from __future__ import print_function
import requests
import re
from collections import namedtuple

Device = namedtuple("Device", ["signal","ip","name","mac","type","link_rate"])

class Netgear(object):

    def __init__(self, host, username, password):
        self.soap_url = "http://{}:5000/soap/server_sa/".format(host)
        self.username = username
        self.password = password
        self.logged_in = False

    def login(self):
        message = SOAP_LOGIN.format(session_id=SESSION_ID,
                                    username=self.username,
                                    password=self.password)

        success, response = self._make_request(ACTION_LOGIN,
                                               message, False)

        self.logged_in = success

        return self.logged_in

    def get_attached_devices(self):
        """ Returns a list of devices. """
        if not self.logged_in:
            self.login()

        message = SOAP_ATTACHED_DEVICES.format(session_id=SESSION_ID)

        success, response = \
            self._make_request(ACTION_GET_ATTACHED_DEVICES, message)

        if success:
            data = re.search(r"<NewAttachDevice>(.*)</NewAttachDevice>",
                             response).group(1).split(";")

            devices = []

            # len(data)-1 because the last element is not used
            for i in range(0, len(data)-1, 6):
                signal = int(data[i].split("@")[0])
                link_rate = int(data[i+5]) if data[i+5] else None

                atts = [signal] + data[i+1:i+5] + [link_rate]

                devices.append(Device(*atts))

            return devices

        else:
            return []


    def _make_request(self, action, message, try_login_after_failure=True):
        headers = _get_soap_header(action)

        try:
            req = requests.post(self.soap_url,
                                headers=headers,
                                data=message,
                                timeout=3)

            success = _is_valid_response(req)

            if not success and try_login_after_failure:
                self.login()

                req = requests.post(self.soap_url,
                                    headers=headers,
                                    data=message,
                                    timeout=3)

            return _is_valid_response(req), req.text

        except requests.exceptions.RequestException:
            # Maybe one day we will distinguish between
            # different errors..
            return False, ""


def _get_soap_header(action):
    return {"SOAPAction": action}

def _is_valid_response(resp):
    return (resp.status_code == 200 and 
            "<ResponseCode>000</ResponseCode>" in resp.text)


ACTION_LOGIN = "urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate"
ACTION_GET_ATTACHED_DEVICES = "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetAttachDevice"

# Until we know how to generate it, give the one we captured
SESSION_ID = "A7D88AE69687E58D9A00"

SOAP_LOGIN = """<?xml version="1.0" encoding="utf-8" ?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header>
<SessionID xsi:type="xsd:string" xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance">{session_id}</SessionID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<Authenticate>
  <NewUsername>{username}</NewUsername>
  <NewPassword>{password}</NewPassword>
</Authenticate>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

SOAP_ATTACHED_DEVICES = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAPSDK1="http://www.w3.org/2001/XMLSchema" xmlns:SOAPSDK2="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAPSDK3="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header>
<SessionID>{session_id}</SessionID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<M1:GetAttachDevice xmlns:M1="urn:NETGEAR-ROUTER:service:DeviceInfo:1">
</M1:GetAttachDevice>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("To test: python pynetgear.py <host> <user> <pass>")
        exit()

    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    netgear = Netgear(host, username, password)

    for i in netgear.get_attached_devices():
        print(i)


