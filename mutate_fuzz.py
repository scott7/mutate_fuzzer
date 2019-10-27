"""
Junos XML RPC API fuzzer (junoscript / NETCONF) post authentication
Requires PyEZ module from Juniper to be installed:
https://github.com/Juniper/py-junos-eznc
"""
import sys
import argparse
import getpass
from lib.mutate_fuzzer import Fuzz

def main():
    """
    Loop through commands list and start sending requests
    """
    parser = argparse.ArgumentParser(description='Send fuzzing data to Junos device')
    parser.add_argument('-n','--numloops', type=int,
                        help='number of times to loop thru fuzzed data (min 110 test cases) (default: 1)')
    parser.add_argument('-c', '--connection', choices=['telnet','ssh'],
                        help="connection type (ssh/telnet default: telnet)")
    parser.add_argument('-i', '--ip', required=True,
                        help="hostname or IP")
    parser.add_argument('-u', '--user',
                        help="username", required=True)

    args = parser.parse_args()
    if args.numloops:
        num_cases = args.numloops
    else:
        num_cases = 1

    if not args.connection:
        print("using telnet - not secure")
        connection_type = 'telnet'
        port = 23

    if args.connection == 'ssh':
        print("using ssh")
        connection_type = None
        port = 22
    else:
        connection_type = 'telnet'
        port = 23

    try:
        password = getpass.getpass(prompt='Password: ', stream=None) 
    except Exception as e:
        print(f'Failed to parse password: {e}')
        sys.exit(1)

    print("Password received")

    f = Fuzz(host=args.ip, user=args.user, password=password , mode=connection_type, port=port)

    commands_list = ["show system uptime", "not valid", "show version", "show interfaces",
                    "show authentication-whitelist", "show arp", "show arp hostname",
                    "show network-access aaa statistics detail authentication",
                    "show network-access", "show firewall"]

    # Run test commnand without fuzzing to ensure connection works
    send_regular_command = f.send_xml_command("show system uptime")
    if send_regular_command is not None and str(send_regular_command.tag) == 'multi-routing-engine-results':
        print('Test command succeeded')
    else:
        print(f'Test command failed. Stopping. --> {send_regular_command}')
        sys.exit(1)

    print("STARTING FUZZING - writing to json file for logs")
    print("")
    f.mutate_fuzzer(commands_list = commands_list, num_cases = num_cases)

if __name__ == "__main__":
    main()
