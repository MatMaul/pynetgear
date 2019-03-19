"""Run PyNetgear from the command-line."""
import sys
import os

from argparse import ArgumentParser
from collections.abc import Iterable
from pynetgear import Netgear, BLOCK, ALLOW


def make_formatter(format_name):
    """Returns a callable that outputs the data. Defaults to print."""

    if format_name == "json":
        from json import dumps

        def jsonify(data):
            if isinstance(data, Iterable):
                if isinstance(data, dict):
                    print(dumps(data))
                else:
                    print(dumps([device._asdict() for device in data]))
            else:
                print(dumps({'result': data}))
        return jsonify
    else:
        def printer(data):
            if isinstance(data, Iterable):
                print(data)
            else:
                for row in data:
                    print(row)
        return printer


def argparser():
    """Constructs the ArgumentParser for the CLI"""

    parser = ArgumentParser(prog='pynetgear')

    parser.add_argument("--format", choices=['json', 'py'], default='py')

    router_args = parser.add_argument_group("router connection config")
    router_args.add_argument("--host", help="Hostname for the router")
    router_args.add_argument("--user", help="Account for login")
    router_args.add_argument("--port", help="Port exposed on the router")
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

    block_parser = subparsers.add_parser(
            "block_device",
            help="Blocks a device from connecting by mac address")
    block_parser.add_argument("--mac-addr")

    allow_parser = subparsers.add_parser(
            "allow_device",
            help="Allows a device with the mac address to connect")
    allow_parser.add_argument("--mac-addr")

    subparsers.add_parser("login", help="Attempts to login to router.")

    attached_devices = subparsers.add_parser("attached_devices", help="Outputs all attached devices")
    attached_devices.add_argument(
            "-v", "--verbose",
            action="store_true",
            default=False,
            help="Choose between verbose and slower or terse and fast.")

    subparsers.add_parser("traffic_meter", help="Output router's traffic meter data")

    return parser


def run_subcommand(netgear, args):
    """Runs the subcommand configured in args on the netgear session"""

    subcommand = args.subcommand

    if subcommand == "block_device" or subcommand == "allow_device":
        return netgear.allow_block_device(args.mac_addr, BLOCK if subcommand == "block_device" else ALLOW)

    if subcommand == "attached_devices":
        if args.verbose:
            return netgear.get_attached_devices_2()
        else:
            return netgear.get_attached_devices()

    if subcommand == 'traffic_meter':
        return netgear.get_traffic_meter()

    if subcommand == 'login':
        return netgear.login()

    print("Unknown subcommand")


def main():
    """Scan for devices and print results."""

    args = argparser().parse_args(sys.argv[1:])
    password = os.environ.get('PYNETGEAR_PASSWORD') or args.password

    netgear = Netgear(password, args.host, args.user, args.port, args.ssl, args.url)

    results = run_subcommand(netgear, args)
    formatter = make_formatter(args.format)

    if results is None:
        print("Error communicating with the Netgear router")

    else:
        formatter(results)


if __name__ == '__main__':
    main()
