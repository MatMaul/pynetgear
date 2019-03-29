# encoding: utf-8
"""Constants for pynetgear."""

# ---------------------
# DEFAULTS
# ---------------------
DEFAULT_HOST = 'routerlogin.net'
DEFAULT_USER = 'admin'
DEFAULT_PORT = 5000

BLOCK = "Block"
ALLOW = "Allow"

UNKNOWN_DEVICE_DECODED = '<unknown>'
UNKNOWN_DEVICE_ENCODED = '&lt;unknown&gt;'

REGEX_ATTACHED_DEVICES = r"<NewAttachDevice>(.*)</NewAttachDevice>"

# Until we know how to generate it, give the one we captured
SESSION_ID = "A7D88AE69687E58D9A00"

# ---------------------
# SERVICE
# ---------------------
SERVICE_PREFIX = "urn:NETGEAR-ROUTER:service:"
SERVICE_DEVICE_INFO = "DeviceInfo:1"
SERVICE_DEVICE_CONFIG = "DeviceConfig:1"
SERVICE_PARENTAL_CONTROL = "ParentalControl:1"
SERVICE_ADVANCED_QOS = "AdvancedQoS:1"
SERVICE_WLAN_CONFIGURATION = "WLANConfiguration:1"

# ---------------------
# SERVICE_DEVICE_CONFIG
# ---------------------
LOGIN = 'SOAPLogin'
# LOGOUT = 'SOAPLogout'
REBOOT = 'Reboot'
CHECK_NEW_FIRMWARE = 'CheckNewFirmware'
# UPDATE_NEW_FIRMWARE = 'UpdateNewFirmware'
CONFIGURATION_STARTED = 'ConfigurationStarted'
CONFIGURATION_FINISHED = 'ConfigurationFinished'

# BLOCK/ALLOW DEVICE
SET_BLOCK_DEVICE_ENABLE = 'SetBlockDeviceEnable'
GET_BLOCK_DEVICE_ENABLE_STATUS = 'GetBlockDeviceEnableStatus'
# ENABLE_BLOCK_DEVICE_FOR_ALL = 'EnableBlockDeviceForAll'  # deprecated?
SET_BLOCK_DEVICE_BY_MAC = 'SetBlockDeviceByMAC'

# TRAFFIC METER
GET_TRAFFIC_METER_STATISTICS = 'GetTrafficMeterStatistics'
ENABLE_TRAFFIC_METER = 'EnableTrafficMeter'
GET_TRAFFIC_METER_ENABLED = 'GetTrafficMeterEnabled'
# SET_TRAFFIC_METER_OPTIONS = 'SetTrafficMeterOptions'
GET_TRAFFIC_METER_OPTIONS = 'GetTrafficMeterOptions'

# ---------------------
# SERVICE_PARENTAL_CONTROL
# ---------------------
LOGIN_OLD = 'Authenticate'
ENABLE_PARENTAL_CONTROL = 'EnableParentalControl'
GET_PARENTAL_CONTROL_ENABLE_STATUS = 'GetEnableStatus'
GET_ALL_MAC_ADDRESSES = 'GetAllMACAddresses'
# SET_DNS_MASQ_DEVICE_ID = 'SetDNSMasqDeviceID'
GET_DNS_MASQ_DEVICE_ID = 'GetDNSMasqDeviceID'
# DELETE_MAC_ADDRESS = 'DeleteMACAddress'

# ---------------------
# SERVICE_DEVICE_INFO
# ---------------------
GET_INFO = 'GetInfo'
GET_SUPPORT_FEATURE_LIST_XML = 'GetSupportFeatureListXML'
GET_ATTACHED_DEVICES = 'GetAttachDevice'
GET_ATTACHED_DEVICES_2 = 'GetAttachDevice2'
# SET_DEVICE_NAME_ICON_BY_MAC = 'SetDeviceNameIconByMAC'

# ---------------------
# SERVICE_ADVANCED_QOS
# ---------------------
SET_SPEED_TEST_START = 'SetOOKLASpeedTestStart'
GET_SPEED_TEST_RESULT = 'GetOOKLASpeedTestResult'
SET_QOS_ENABLE_STATUS = 'SetQoSEnableStatus'
GET_QOS_ENABLE_STATUS = 'GetQoSEnableStatus'
# SET_BANDWIDTH_CONTROL_OPTIONS = 'SetBandwidthControlOptions'
GET_BANDWIDTH_CONTROL_OPTIONS = 'GetBandwidthControlOptions'
GET_CURRENT_APP_BANDWIDTH = 'GetCurrentAppBandwidth'  # Not Working
GET_CURRENT_DEVICE_BANDWIDTH = 'GetCurrentDeviceBandwidth'  # Not Working
GET_CURRENT_APP_BANDWIDTH_BY_MAC = 'GetCurrentAppBandwidthByMAC'  # Not Working

# ---------------------
# SERVICE_WLAN_CONFIGURATION
# ---------------------
SET_GUEST_ACCESS_ENABLED = 'SetGuestAccessEnabled'  # 2.4G-1 R7800
GET_GUEST_ACCESS_ENABLED = 'GetGuestAccessEnabled'  # 2.4G-1 R7800/R8000
SET_GUEST_ACCESS_ENABLED_2 = 'SetGuestAccessEnabled2'  # 2.4G-1 R8000
GET_GUEST_ACCESS_ENABLED_2 = 'GetGuestAccessEnabled2'  # 2.4G-1 R8000
SET_5G_GUEST_ACCESS_ENABLED = 'Set5GGuestAccessEnabled'  # 5G-1 R7800
GET_5G1_GUEST_ACCESS_ENABLED = 'Get5GGuestAccessEnabled'  # 5G-1 R7800
GET_5G1_GUEST_ACCESS_ENABLED_2 = 'Get5G1GuestAccessEnabled'  # 5G-1 R8000
SET_5G1_GUEST_ACCESS_ENABLED_2 = 'Set5G1GuestAccessEnabled2'  # 5G-1 R8000
SET_5G_GUEST_ACCESS_ENABLED_2 = 'Set5GGuestAccessEnabled2'  # 5G-2 R8000
GET_5G_GUEST_ACCESS_ENABLED_2 = 'Get5GGuestAccessEnabled2'  # 5G-2 R8000
GET_WPA_SECURITY_KEYS = 'GetWPASecurityKeys'
GET_5G_WPA_SECURITY_KEYS = 'Get5GWPASecurityKeys'
GET_2G_INFO = 'GetInfo'
GET_5G_INFO = 'Get5GInfo'
# SET_5G_WLAN_WPA_PSK_BY_PASSPHRASE = 'Set5GWLANWPAPSKByPassphrase'
GET_AVAILABLE_CHANNEL = 'GetAvailableChannel'
# SET_GUEST_ACCESS_NETWORK = 'SetGuestAccessNetwork'
GET_GUEST_ACCESS_NETWORK_INFO = 'GetGuestAccessNetworkInfo'
# SET_5G_GUEST_ACCESS_NETWORK = 'Set5GGuestAccessNetwork'
GET_5G_GUEST_ACCESS_NETWORK_INFO = 'Get5GGuestAccessNetworkInfo'

# ---------------------
# FORMATTING
# ---------------------
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
