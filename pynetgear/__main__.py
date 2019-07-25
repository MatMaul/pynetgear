# encoding: utf-8
"""Run PyNetgear from the command-line."""
import sys
import os

from argparse import ArgumentParser
from . import Netgear  # pylint: disable=relative-beyond-top-level
from .const import ALLOW, BLOCK  # pylint: disable=relative-beyond-top-level
from .commands import COMMANDS  # pylint: disable=relative-beyond-top-level


def make_formatter(format_name):  # noqa  # pylama C901
    """Return a callable that outputs the data. Defaults to print."""
    if "json" in format_name:
        from json import dumps
        import datetime

        def jsonhandler(obj):
            if isinstance(obj, (datetime.datetime, datetime.date)):
                return obj.isoformat()

            return obj

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
            "-p", "--password",
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
            dest="subcommand", metavar="")

    # loop through COMMANDS and create the cli args
    for command, value in COMMANDS.items():

        if len(value) == 3:
            strAddParser = subparsers.add_parser(command, help=value[1])

            for _, aArgs in value[2].items():

                if aArgs[2]:
                    strAddParser.add_argument(
                        aArgs[0], aArgs[1],
                        help=aArgs[4], choices=aArgs[2])

                elif aArgs[3] == 'store_true':
                    strAddParser.add_argument(
                        aArgs[0], aArgs[1], help=aArgs[4],
                        action='store_true', default=False)

                else:
                    strAddParser.add_argument(
                        aArgs[0], aArgs[1], help=aArgs[4])

        else:
            subparsers.add_parser(command, help=value[1])

    return parser


def run_subcommand(netgear, args):  # noqa  # pylama C901
    """Run the subcommand configured in args on the netgear session."""
    subcommand = args.subcommand
    response = None

    if subcommand in COMMANDS:
        theFunction = COMMANDS[subcommand][0]
        test = False
        verbose = False
        enable = False
        mac = False
        action = None
        if hasattr(args, 'test'):
            test = args.test
        if hasattr(args, 'verbose'):
            verbose = args.verbose
        if hasattr(args, 'enable'):
            enable = args.enable
        if hasattr(args, 'mac'):
            mac = args.mac
        if hasattr(args, 'action'):
            action = args.action

        # MOST functions have a test argument
        # Handle verbose cl arg
        if verbose:
            response = getattr(netgear, 'get_attached_devices_2')(test)
        # Special case for block device
        elif subcommand == 'block_device_cli':
            theAction = BLOCK
            if action == 'allow':
                theAction = ALLOW
            response = getattr(netgear, theFunction)(test, mac, theAction)
        # If enable = y|n
        elif enable:
            response = getattr(netgear, theFunction)(test, enable)
        # if command with test, and test=true
        elif test:
            response = getattr(netgear, theFunction)(test)
        # fallback
        else:
            response = getattr(netgear, theFunction)()

    else:
        print("Unknown subcommand")

    return response


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
