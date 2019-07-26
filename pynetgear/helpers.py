# encoding: utf-8
"""Helper functions for pynetgear."""
from io import StringIO
import xml.etree.ElementTree as ET
import re
import sys
import requests
import logging
from datetime import timedelta

from .const import SERVICE_PREFIX  # pylint: disable=relative-beyond-top-level

_LOGGER = logging.getLogger(__name__)

# define regex to filter invalid XML codes
# cf https://stackoverflow.com/questions/1707890/fast-way-to-filter-illegal-xml
# -unicode-chars-in-python
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


def to_get(parseNode, toParse, response):
    """Create a dict of the node information."""
    success, theNode = find_node(response.text, parseNode)

    if not success:
        return False

    theInfo = {}

    for x in toParse:
        theItem = xml_get(theNode, x)
        if theItem:
            theInfo[x] = theItem
        else:
            theInfo[x] = None

    return theInfo


def autodetect_url():
    """
    Try to autodetect the base URL of the router SOAP service.

    Returns None if it can't be found.
    """
    for url in ["http://routerlogin.net:5000", "https://routerlogin.net",
                "http://routerlogin.net"]:
        try:
            r = requests.get(url + "/soap/server_sa/",
                             headers=get_soap_headers("Test:1", "test"),
                             verify=False)
            if r.status_code == 200:
                return url
        except requests.exceptions.RequestException:
            pass

    return None


def find_node(text, xpath):
    """Look for a node in xml."""
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


def xml_get(e, name):
    """
    Return the value of the subnode "name" of element e.

    Return None if the subnode doesn't exist
    """
    r = e.find(name)
    if r is not None:
        return r.text
    return None


def get_soap_headers(service, method):
    """Return Soap Headers."""
    action = SERVICE_PREFIX + service + "#" + method
    return {
        "SOAPAction":    action,
        "Cache-Control": "no-cache",
        "User-Agent":    "pynetgear",
        "Content-Type":  "multipart/form-data"
    }


def is_valid_response(resp):
    """Check if is valid."""
    return (resp.status_code == 200 and
            ("<ResponseCode>0000</ResponseCode>" in resp.text or
             "<ResponseCode>000</ResponseCode>" in resp.text or
             # Speed Test Result
             "<ResponseCode>2</ResponseCode>" in resp.text or
             # dns_masq/mac_address
             "<ResponseCode>001</ResponseCode>" in resp.text
             ))


def is_unauthorized_response(resp):
    """Check if is unauthorized."""
    return (resp.status_code == 401 or
            "<ResponseCode>401</ResponseCode>" in resp.text)


def convert(value, to_type, default=None):
    """Convert value to to_type, returns default if fails."""
    try:
        return default if value is None else to_type(value)
    except ValueError:
        # If value could not be converted
        return default


def parse_text(text):
    """
    There are three kinds of values in the returned data.

    This function parses the different values and returns
    (total, avg), timedelta or a plain float
    """
    def tofloats(lst):
        return (float(t) for t in lst)
    try:
        if "/" in text:  # "6.19/0.88" total/avg
            return tuple(tofloats(text.split('/')))

        if ":" in text:  # 11:14 hr:mn
            hour, mins = tofloats(text.split(':'))
            return timedelta(hours=hour, minutes=mins)

        return float(text)
    except ValueError:
        return None


def value_to_zero_or_one(s):
    """Convert value to 1 or 0 string."""
    if isinstance(s, str):
        if s.lower() in ('true', 't', 'yes', 'y', '1'):
            return '1'
        if s.lower() in ('false', 'f', 'no', 'n', '0'):
            return '0'
    if isinstance(s, bool):
        if s:
            return '1'
        return '0'

    raise ValueError("Cannot covert {} to a 1 or 0".format(s))
