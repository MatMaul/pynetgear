# encoding: utf-8
"""Dict of COMMANDS."""
# arg: [function, help, args:{
#           shortCommand, LongCommand, choices
#           store_true, help
#       }]

COMMANDS = {
    # ---------------------
    # SERVICE_DEVICE_CONFIG
    # ---------------------
    'login': ['login', 'Attempts to login to router'],
    'reboot': ['reboot', 'Reboot Router', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'check_fw': ['check_new_firmware', 'Check for new firmware', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
            }
        ],
    # value/test
    'enable_block_device': [
        'set_block_device_enable', 'Enable Access Control', {
            'enable': [
                '-e', '--enable',
                'yn', False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'block_device_status': [
        'get_block_device_enable_status', 'Get Access Control Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'enable_traffic_meter': [
        'enable_traffic_meter', 'Enable/Disable Traffic Meter',
        {
            'enable': [
                '-e', '--enable', 'yn',
                False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'traffic_meter': [
        'get_traffic_meter_statistics', 'Get Traffic Meter Statistics', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'traffic_meter_enabled': [
        'get_traffic_meter_enabled', 'Get Traffic Meter Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'traffic_meter_options': [
        'get_traffic_meter_options', 'Get Traffic Meter Options', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # ---------------------
    # SERVICE_PARENTAL_CONTROL
    # ---------------------
    # value/test
    'enable_parental_control': [
        'enable_parental_control', 'Enable/Disable Parental Control',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'parental_control_status': [
        'get_parental_control_enable_status', 'Get Parental Control Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'mac_address': [
        'get_all_mac_addresses', 'Get all MAC Addresses', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'dns_masq': [
        'get_dns_masq_device_id', 'Get DNS Masq Device ID', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # ---------------------
    # SERVICE_DEVICE_INFO
    # ---------------------
    'info': [
        'get_info', 'Get Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'support_feature': [
        'get_support_feature_list_XML', 'Get Supported Features', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'attached_devices': [
        'attached_devices', 'Get Attached Devices', {
            'verbose': ['-v', '--verbose', False, 'store_true', False],
        }
    ],
    'attached_devices2': [
        'attached_devices2', 'Get Attached Devices 2'],
    # ---------------------
    # SERVICE_ADVANCED_QOS
    # ---------------------
    'speed_test_start': [
        'set_speed_test_start', 'Start Speed Test', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'speed_test_result': [
        'get_speed_test_result', 'Get Speed Test Results', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'qos_enabled': [
        'get_qos_enable_status', 'Get QOS Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'emable_qos': [
        'set_qos_enable_status', 'Enable/Disable QOS',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'bw_control': [
        'get_bandwidth_control_options', 'Get Bandwidth Control Options'],
    # ---------------------
    # SERVICE_WLAN_CONFIGURATION
    # ---------------------
    # value/test
    'guest_access_enable': [
        'guest_access_enable', 'Enable/Disable Guest 2.4G Wifi',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'guest_access': [
        'guest_access', 'Get 2G Guest Wifi Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'guest_access_enable2': [
        'guest_access_enable2', 'Enable/Disable Guest 2.4G Wifi',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # 'guest_access2': ['guest_access2', 'get_guest_access_enabled2'],
    # value/test
    'guest_access_enable_5g': [
        'guest_access_enable_5g', 'Enable/Disable Guest 5G Wifi',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'guest_access_5g': [
        'guest_access_5g', 'Get 5G Guest Wifi Status', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'guest_access_enable_5g1': [
        'guest_access_enable_5g1', 'Enable/Disable Guest 5G Wifi2',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # 'guest_access_5g1':[
    #    'guest_access_5g1', 'get_5g1_guest_access_enabled_2'],

    # value/test
    'guest_access_enable_5g2': [
        'guest_access_enable_5g2', 'Enable/Disable Guest 5G Wifi3',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    # 'guest_access_5g2': [
    #    'guest_access_5g2', 'get_5g_guest_access_enabled_2'],

    'wpa_key': [
        'wpa_key', 'Get 2G WPA Key', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'wpa_key_5g': [
        'wpa_key_5g', 'Get 5G WPA Key', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'get_2g_info': [
        'get_2g_info', 'Get 2G Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'get_5g_info': [
        'get_5g_info', 'Get 5G Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'guest_access_net': [
        'guest_access_net', 'Get 2G Guest Wifi Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
    'guest_access_net_5g': [
        'guest_access_net_5g', 'Get 5G Guest Wifi Info', {
            'test': [
                '-t', '--test', False,
                'store_true', 'Output SOAP Response'],
        }
    ],
}
