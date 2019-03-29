"""Run PyNetgear from the command-line."""
import sys
import os

from argparse import ArgumentParser
from . import Netgear
from .const import ALLOW, BLOCK

# arg: [function, help, args:{arg1: choice, arg2: choice}]
COMMANDS = {
    # ---------------------
    # SERVICE_DEVICE_CONFIG
    # ---------------------
    'login': ['login', 'Attempts to login to router'],
    'reboot': ['reboot', 'Reboot Router',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'check_fw': ['check_new_firmware', 'Check for new firmware',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'enable_block_device': ['set_block_device_enable', 'Enable Access Control',
        { 
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'block_device_status': ['get_block_device_enable_status', 'Get Access Control Status',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'enable_traffic_meter': ['enable_traffic_meter', 'Enable/Disable Traffic Meter',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'traffic_meter': ['get_traffic_meter_statistics', 'Get Traffic Meter Statistics',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'traffic_meter_enabled': ['get_traffic_meter_enabled', 'Get Traffic Meter Status',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'traffic_meter_options': ['get_traffic_meter_options', 'Get Traffic Meter Options',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # ---------------------
    # SERVICE_PARENTAL_CONTROL
    # ---------------------
    # value/test
    'enable_parental_control': ['enable_parental_control', 'Enable/Disable Parental Control',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'parental_control_status': ['get_parental_control_enable_status', 'Get Parental Control Status',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'mac_address': ['get_all_mac_addresses', 'Get all MAC Addresses',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'dns_masq': ['get_dns_masq_device_id', 'Get DNS Masq Device ID',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # ---------------------
    # SERVICE_DEVICE_INFO
    # ---------------------
    'info': ['get_info', 'Get Info',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'support_feature': ['get_support_feature_list_XML', 'Get Supported Features',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'attached_devices': ['attached_devices', 'Get Attached Devices',
        { 
            'verbose': ['-v', '--verbose', False, 'store_true', False],
        }
    ],
    'attached_devices2': ['attached_devices2', 'Get Attached Devices 2'],
    # ---------------------
    # SERVICE_ADVANCED_QOS
    # ---------------------
    'speed_test_start': ['set_speed_test_start', 'Start Speed Test',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'speed_test_result': ['get_speed_test_result', 'Get Speed Test Results',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'qos_enabled': ['get_qos_enable_status', 'Get QOS Status',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'emable_qos': ['set_qos_enable_status', 'Enable/Disable QOS',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'bw_control': ['get_bandwidth_control_options', 'Get Bandwidth Control Options'],
    # ---------------------
    # SERVICE_WLAN_CONFIGURATION
    # ---------------------
    # value/test
    'guest_access_enable': ['guest_access_enable', 'Enable/Disable Guest 2.4G Wifi',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'guest_access': ['guest_access', 'Get 2G Guest Wifi Status',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'guest_access_enable2': ['guest_access_enable2', 'Enable/Disable Guest 2.4G Wifi',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # 'guest_access2': ['guest_access2', 'get_guest_access_enabled2'],
    # value/test
    'guest_access_enable_5g': ['guest_access_enable_5g', 'Enable/Disable Guest 5G Wifi',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'guest_access_5g': ['guest_access_5g', 'Get 5G Guest Wifi Status',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # value/test
    'guest_access_enable_5g1': ['guest_access_enable_5g1', 'Enable/Disable Guest 5G Wifi2',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # 'guest_access_5g1':[ 'guest_access_5g1', 'get_5g1_guest_access_enabled_2'],
    # value/test
    'guest_access_enable_5g2': ['guest_access_enable_5g2', 'Enable/Disable Guest 5G Wifi3',
        {
            'enable': ['-e', '--enable', 'yn', False, False],
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    # 'guest_access_5g2': ['guest_access_5g2', 'get_5g_guest_access_enabled_2'],
    'wpa_key': ['wpa_key', 'Get 2G WPA Key',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'wpa_key_5g': ['wpa_key_5g', 'Get 5G WPA Key',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'get_2g_info': ['get_2g_info', 'Get 2G Info',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'get_5g_info': ['get_5g_info', 'Get 5G Info',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'guest_access_net': ['guest_access_net', 'Get 2G Guest Wifi Info',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
    'guest_access_net_5g': ['guest_access_net_5g', 'Get 5G Guest Wifi Info',
        { 
            'test': ['-t', '--test', False, 'store_true', 'Output SOAP Response'],
        }
    ],
}


def make_formatter(format_name):  # noqa
    """Returns a callable that outputs the data. Defaults to print."""

    if "json" in format_name:
        from json import dumps
        import datetime

        def jsonhandler(obj):
            if isinstance(obj, (datetime.datetime, datetime.date)):
                obj.isoformat()
            else:
                obj

        if format_name == "prettyjson":
            def jsondumps(data):
                return dumps(
                    data, default=jsonhandler, indent=2, separators=(',', ': ')
                )
        else:
            def jsondumps(data):
                return dumps(data, default=jsonhandler)

        def jsonify(data):
            if isinstance(data, dict):
                print(jsondumps(data))
            elif isinstance(data, list):
                print(jsondumps([device._asdict() for device in data]))
            else:
                print(dumps({'result': data}))
        return jsonify
    else:
        def printer(data):
            if isinstance(data, dict):
                print(data)
            else:
                for row in data:
                    print(row)
        return printer


def argparser():
    """Construct the ArgumentParser for the CLI."""
    parser = ArgumentParser(prog='pynetgear')

    parser.add_argument(
        "--format", choices=['json', 'prettyjson', 'py'], default='prettyjson'
        )

    # Connection Config
    router_args = parser.add_argument_group("router connection config")
    router_args.add_argument("--host", help="Hostname for the router")
    router_args.add_argument("--user", help="Account for login")
    router_args.add_argument("--port", help="Port exposed on the router")
    router_args.add_argument(
        "--login-v2", help="Force the use of the cookie-based authentication",
        dest="force_login_v2", default=False, action="store_true"
        )
    router_args.add_argument(
            "--password",
            help="Not required with a wired connection." +
                 "Optionally, set the PYNETGEAR_PASSWORD environment variable")
    router_args.add_argument(
            "--url", help="Overrides host:port and ssl with url to router")
    router_args.add_argument("--no-ssl",
                             dest="ssl", default=True,
                             action="store_false",
                             help="Connect with https")

    subparsers = parser.add_subparsers(
            description="Runs subcommand against the specified router",
            dest="subcommand")

    # Block
    block_parser = subparsers.add_parser(
            "block_device",
            help="Blocks a device from connecting by mac address")
    block_parser.add_argument("--mac-addr")

    # Allow
    allow_parser = subparsers.add_parser(
            "allow_device",
            help="Allows a device with the mac address to connect")
    allow_parser.add_argument("--mac-addr")

    for command, value in COMMANDS.items():
        functionStr = value[0]
        helpStr = value[1]

        if len(value) == 3:
            strAddParser = subparsers.add_parser(command, help=helpStr)

            for aCommand, aChoice in value[2].items():
                theComShort = aChoice[0]
                theComLong = aChoice[1]
                theChoice = aChoice[2]
                theAction = aChoice[3]
                theHelp = aChoice[4]

                if theChoice:
                    strAddParser.add_argument(theComShort, theComLong, help=theHelp, choices=theChoice)

                if theAction == 'store_true':
                    strAddParser.add_argument(theComShort, theComLong, help=theHelp, action='store_true', default=False)

        else:
            subparsers.add_parser(command, help=helpStr)

    return parser


def run_subcommand(netgear, args):
    """Run the subcommand configured in args on the netgear session."""
    subcommand = args.subcommand

    print(subcommand)
    if subcommand in COMMANDS:
        response = None
        theFunction = COMMANDS[subcommand][0]
        test = False
        verbose = False
        if hasattr(args, 'test'):
            test = args.test
        if hasattr(args, 'verbose'):
            verbose = args.verbose
        #print(theFunction)
        #print(args)

        if subcommand in ("block_device", "allow_device"):
            response = netgear.set_block_device_by_mac(
                args.mac_addr, BLOCK if subcommand == "block_device" else ALLOW
                )
        
        if subcommand == "attached_devices":
            if args.verbose:
                response = getattr(netgear, get_attached_devices_2)()
            response = getattr(netgear, get_attached_devices)()

        # Not every function has a test
        if test:
            response = getattr(netgear, theFunction)(test)

        else:
            response = getattr(netgear, theFunction)()

        return response


    print("Unknown subcommand")

def main():
    """Scan for devices and print results."""
    args = argparser().parse_args(sys.argv[1:])
    password = os.environ.get('PYNETGEAR_PASSWORD') or args.password

    netgear = Netgear(
        password, args.host, args.user, args.port,
        args.ssl, args.url, args.force_login_v2
        )

    results = run_subcommand(netgear, args)
    formatter = make_formatter(args.format)

    if results is None:
        print("Error communicating with the Netgear router")

    else:
        formatter(results)


if __name__ == '__main__':
    main()
