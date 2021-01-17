import requests
import json
import subprocess
from pprint import pprint
import argparse
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import time
from datetime import datetime
import os

MAX_TRIES = 3
DEBUG = False
# python detect.py --input resources/test.json --interface en0
# --results-file results/censorship_result.json --output-path output

# Censored Query: curl -H "Host: groups.google.com" 120.77.156.227
# Censored Query: curl -H "Host: google.com.sa" 114.55.249.66

def main(config):
    with open(config.input) as file:
        ASN_IPs = json.load(file)

    build_go_measurement_app()

    output_path = config.output_path
    output_path = os.path.join(output_path, datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f"))

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    results = {}
    for ASN in ASN_IPs:
        count = 1
        for data in ASN_IPs[ASN]:
            pprint("[*] " + str(count) + " [Scan App] IP:" + data['IP'] + " | Domain: " + data['Domain'])
            detect_censorship_test = CensorshipTest(data['IP'], data['Domain'], output_path)
            detect_results, censored = detect_censorship_test.run()

            results[data['IP']] = {
                'IP': data['IP'],
                'Domain': data['Domain'],
                'ASN': ASN,
                'Results': detect_results
            }

            if censored == True:
                count += 1

            if count >= 50:
                continue

    with open(config.results_file, 'w') as outfile:
        json.dump(results, outfile, indent=4)


class CensorshipTest:
    """
    Represents the IP, Domain to test for censorship and validate it against the result
    provided by the go measurement app given the pcap generated during the request
    """
    def __init__(self, ip, domain, output_folder):
        self.ip = ip
        self.domain = domain

        self.output_folder = output_folder

    def run(self):
        """
        Runs censorship detection as many times as MAX_TRIES is specified
        :return: results (list of objects of length MAX_TRIES)
        """
        # Choose random local port for request
        local_port = int(random.uniform(1025, 65530))
        censored_all = False

        results = []
        start_port = local_port
        while local_port < start_port + MAX_TRIES:
            # Start tcpdump
            naming = self.domain.replace('.', '_')
            pcap_file = os.path.join(self.output_folder, naming + "_" + str(local_port) + ".pcap")
            pcap_capture_process = CensorshipTest.start_tcpdump(pcap_file, local_port)

            # Perform Request
            censored, err = CensorshipTest.request(self.ip, self.domain, local_port)

            # Close tcpdump
            time.sleep(10)  # Buffer for new packets
            pcap_capture_process.send_signal(subprocess.signal.SIGTERM)
            subprocess.Popen("sudo pkill -f tcpdump", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            time.sleep(3)

            # Compare with go measurement
            go_log_file = os.path.join(self.output_folder, naming + "_" + str(local_port) + ".log")
            go_censorship_result = \
                CensorshipTest.go_measurement_app(go_log_file, pcap_file, local_port)

            # Append results
            results.append({
                'PCAP': pcap_file,
                'Go_log': go_log_file,
                'Censored': censored,
                'RequestError': err,
                'GoMatch': censored == go_censorship_result
            })

            print("Censored: " + str(censored) + "\tGoMatch: " + str(go_censorship_result == censored) +
                  "\tRequestError: " + str(err))

            local_port += 1

            if censored:
                censored_all = True

        return results, censored_all

    @staticmethod
    def start_tcpdump(pcap_file, port=5000):
        """
        Starts tcpdump process and filters on the given the port number.
        """
        # tcpdump command
        tcpdump = "tcpdump" \
                  " -i " + config.interface + \
                  " -n port " + str(port) + \
                  " -w " + pcap_file
        if DEBUG:
            pprint(tcpdump)

        # tcpdump process
        pcap_capture_process = subprocess.Popen(tcpdump, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        time.sleep(2)  # Buffer to ensure that tcpdump is running before returning

        return pcap_capture_process

    @staticmethod
    def request(ip, domain, local_port=5000):
        """
        Performs an HTTP request to the IP and detects whether the request was censored
        """
        # HTTP Header for HTTP request
        header = {
            'Host': domain
        }

        err = None
        censored = False
        s = requests.Session()
        s.mount('http://', SourcePortAdapter(local_port))

        if DEBUG:
            pprint("Making request: " + str(ip) + "|" + str(local_port) +
                    "|" + str(domain) + "|" + str(header))

        try:
            s.get("http://%s/" % ip, headers=header, timeout=5, allow_redirects=False)
        except requests.exceptions.ConnectionError as e:
            if e.__context__ is not None and e.__context__.__context__ is not None:
                if isinstance(e.__context__.__context__, ConnectionResetError):
                    # Censorship Detected
                    censored = True

            err = str(e)
        except Exception as e:
            err = str(e)

        if DEBUG:
            pprint(err)

        return censored, err

    @staticmethod
    def go_measurement_app(log_file, pcap_file, local_port):
        """
        Runs the go measurement app on the pcap generated from the
        HTTP request and returns whether Censorship was detected.
        """
        go_execution = "../bin/tripwire --config-file resources/config_china_http.yml" + \
                       " --pcap " + pcap_file + \
                       " --bpf " + "\"tcp and port " + str(local_port) + "\"" + \
                       " --log-file \"" + log_file + "\""
        if DEBUG:
            pprint(go_execution)
        censorship_detect_app = subprocess.Popen(go_execution, shell=True, stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE)

        censorship_detect_app.wait()
        time.sleep(2)

        with open(log_file, 'r') as fp:
            line = fp.readline()
            while line:
                if "Censorship Detected" in line:
                    return True
                line = fp.readline()

        return False


def build_go_measurement_app():
    """
    Builds go measurement app to make sure the latest version is compiled
    """
    process = subprocess.Popen("cd ../app && /usr/local/go/bin/go build -o ./bin/tripwire ./cmd/tripwire", shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    process.wait()
    if DEBUG:
        pprint("[Build Measurement] STDOUT: " + str(process.stdout.read()))
        pprint("[Build Measurement] STDERR: " + str(process.stderr.read()))
    if process.returncode != 0:
        print("Error building go measurement app. Terminating...")
        exit(1)


# Code from https://stackoverflow.com/questions/47202790/python-requests-how-to-specify-port-for-outgoing-traffic
class SourcePortAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to set the source port."""
    def __init__(self, port, *args, **kwargs):
        self._source_port = port
        super(SourcePortAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, source_address=('', self._source_port))


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--input", help="Censorship Test Input File", action='store', required=True)
    parser.add_argument("--interface", help="Interface to listen on to capture packets", action='store', required=True)
    parser.add_argument("--results-file", help="Path to store censorship results file", action='store', required=True)
    parser.add_argument("--output-path", help="Path to store pcap and log files", action="store", default=None)

    config = parser.parse_args()

    pprint(config)
    return config


if __name__ == '__main__':
    config = parse_args()
    main(config)
