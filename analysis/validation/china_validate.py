#!/usr/bin/env python3
"""
Validation for Hosts flagged as censored in China.

The testing endpoint here has been preconfigured with a large number of ports to use
for testing to avoid the effects of residual censorship.

sudo iptables -t nat -A PREROUTING -p tcp --match multiport --dports 15000:30000 -j REDIRECT --to-port 80
"""

import argparse
import fileinput
import tqdm
import subprocess as sp


def test_http(testing_endpoint, starting_port=15000):
    """
    Reads line by line from stdin and issues a curl to the default testing endpoint with each line as the host header.
    """
    port = starting_port
    for line in tqdm.tqdm(fileinput.input(files="-")):
        host = line.strip()
        try:
            output = sp.run(
                'curl -m 5 -H "Host: %s" %s:%d' % (host, testing_endpoint, port),
                shell=True,
                stdout=sp.PIPE,
                stderr=sp.PIPE,
            )
        except sp.CalledProcessError as exc:
            result = "error"

        if output.stderr and b"Connection reset by peer" in output.stderr:
            result = "censored"
        elif output.stdout:
            result = "uncensored"
        elif output.stderr and b"Connection timed out" in output.stderr:
            result = "timeout"
        else:
            result = "unknown"
        port += 1

        print(",".join([host, result]))


def test_https(testing_endpoint, starting_port=15000):
    """
    Reads line by line from stdin and issues TLS Client Hello to the default testing endpoint with each line as the host header.
    """
    port = starting_port
    for line in tqdm.tqdm(fileinput.input(files="-")):
        host = line.strip()
        try:
            output = sp.run(
                "openssl s_client -connect %s:%d -servername %s"
                % (testing_endpoint, port, host),
                shell=True,
                stdout=sp.PIPE,
                stderr=sp.PIPE,
            )
        except sp.CalledProcessError as exc:
            result = "error"

        if output.stderr and b"wrong version number" in output.stderr:
            result = "uncensored"
        elif output.stderr and b"errno=104" in output.stderr:
            result = "censored"
        elif output.stderr and b"errno=111" in output.stderr:
            result = "timeout"
        else:
            result = "unknown"

        print(",".join([host, result]))
        port += 1


def test(args):
    """
    Starts running tests for the given configuration
    """
    if args.protocol == "http":
        test_http(args.testing_endpoint, args.starting_port)
    elif args.protocol == "https":
        test_https(args.testing_endpoint, args.starting_port)


def get_args():
    """
    Simple arg parser
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "protocol",
        choices=("http", "https"),
        help="Which protocol to test",
        action="store",
    )
    parser.add_argument(
        "testing_endpoint",
        help="IP address of a testing endpoint to test to. Assumes ports 15,000 to 30,000 are redirected to 80.",
        action="store",
    )
    parser.add_argument(
        "--starting-port",
        help="destination port to start with.",
        type=int,
        default=15000,
        action="store",
    )
    return parser.parse_args()


if __name__ == "__main__":
    test(get_args())
