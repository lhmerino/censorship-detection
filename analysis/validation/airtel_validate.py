#!/usr/bin/env python3
"""
Validation for Hosts flagged as censored in Airtel's ISP in India.
"""

import argparse
import fileinput
import tqdm
import subprocess as sp


TESTING_ENDPOINT = "35.184.243.121"


def test_http():
    """
    Reads line by line from stdin and issues a curl to the default testing endpoint with each line as the host header.
    """
    for line in tqdm.tqdm(fileinput.input(files="-")):
        host = line.strip()
        try:
            output = sp.run(
                'curl -m 5 -H "Host: %s" %s' % (host, TESTING_ENDPOINT),
                shell=True,
                stdout=sp.PIPE,
                stderr=sp.PIPE,
            )
        except sp.CalledProcessError as exc:
            result = "error"

        if output.stdout and b"airtel.in" in output.stdout:
            result = "censored"
        elif output.stdout:
            result = "uncensored"
        elif output.stderr and b"Connection timed out" in output.stderr:
            result = "timeout"
        else:
            result = "unknown"

        print(",".join([host, result]))


def test_https():
    """
    Reads line by line from stdin and issues TLS Client Hello to the default testing endpoint with each line as the host header.
    """
    for line in tqdm.tqdm(fileinput.input(files="-")):
        host = line.strip()
        try:
            output = sp.run(
                "openssl s_client -connect %s:80 -servername %s"
                % (TESTING_ENDPOINT, host),
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


def test(args):
    """
    Starts running tests for the given configuration
    """
    if args.protocol == "http":
        test_http()
    elif args.protocol == "https":
        test_https()


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
    return parser.parse_args()


if __name__ == "__main__":
    test(get_args())
