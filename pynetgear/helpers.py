# encoding: utf-8
"""Helper functions for pynetgear."""
from io import StringIO
import xml.etree.ElementTree as ET
import re
import sys
import requests
import logging

from .const import SERVICE_PREFIX

_LOGGER = logging.getLogger(__name__)

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
                headers=get_soap_headers("Test:1", "test"),
                verify=False,
                timeout=1
            )
            if resp.status_code == 200:
                return url
        except requests.exceptions.RequestException:
            pass

    return None


def find_node(text, xpath):
    text = _illegal_xml_chars_RE.sub('', text)

    try:
        it = ET.iterparse(StringIO(text))
        # strip all namespaces
        for _, el in it:
            if '}' in el.tag:
                el.tag = el.tag.split('}', 1)[1]
    except ET.ParseError:
        _LOGGER.error("Error parsing XML response")
        _LOGGER.debug("Error parsing XML response", exc_info=True)
        _LOGGER.debug(text)
        return False, None

    node = it.root.find(xpath)
    if node is None:
        _LOGGER.error("Error finding node in XML response")
        _LOGGER.debug(text)
        return False, None

    return True, node


def xml_get(e, name):
    """
    Returns the value of the subnode "name" of element e.

    Returns None if the subnode doesn't exist
    """
    r = e.find(name)
    if r is not None:
        return r.text
    return None


def get_soap_headers(service, method):
    action = SERVICE_PREFIX + service + "#" + method
    return {
        "SOAPAction":    action,
        "Cache-Control": "no-cache",
        "User-Agent":    "pynetgear",
        "Content-Type":  "multipart/form-data"
    }


def is_valid_response(resp):
    return (resp.status_code == 200 and
            ("<ResponseCode>0000</" in resp.text or
             "<ResponseCode>000</" in resp.text or
             # Speed Test Result
             "<ResponseCode>2</" in resp.text or
             # dns_masq/mac_address
             "<ResponseCode>001</" in resp.text
             ))


def is_unauthorized_response(resp):
    return (resp.status_code == 401 or
            "<ResponseCode>401</ResponseCode>" in resp.text)


def is_service_unavailable_response(resp):
    return (resp.status_code == 503 or
            "<ResponseCode>503</ResponseCode>" in resp.text)


def convert(value, to_type, default=None):
    """Convert value to to_type, returns default if fails."""
    try:
        return default if value is None else to_type(value)
    except ValueError:
        # If value could not be converted
        return default
