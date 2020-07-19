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

MAX_TRIES = 3
DEBUG = False
# python detect.py resources/test.json en0 results/censorship_result.json
# Censored: curl -H "Host: groups.google.com" 120.77.156.227
# Censored: curl -H "Host: google.com.sa" 114.55.249.66


def detect_censorship(config):
    ASN_IPs = get_subjects(config)
    build_go_measurement_app()

    count = 1
    result = {}
    for ASN in ASN_IPs:
        for data in ASN_IPs[ASN]:
            pprint("[*] " + str(count) + " [Scan App] IP:" + data['IP'] + " | Domain: " +data['Domain'])
            censored, err, session_id, go_match = detect_censorship_one(config, data['IP'], data['Domain'])

            result[data['IP']] = {
                'IP': data['IP'],
                'Domain': data['Domain'],
                'ASN': ASN,
                'SessionID': session_id,
                'Censored': censored,
                'RequestError': err,
                'GoMatch': go_match
            }
            pprint("[Scan App:Result] Session: " + str(session_id) + " |Censored: " + str(censored) + " |GoMatch: " +
                   str(go_match) + " |Request Error: " + str(err))
            count += 1
        break

    with open(config.results_file, 'w') as outfile:
        json.dump(result, outfile, indent=4)


def get_subjects(config):
    with open(config.input) as file:
        contents = json.load(file)
        return contents


def detect_censorship_one(config, ip, domain):
    # Choose random local port
    port = int(random.uniform(1025, 65534))

    # Choose a session id
    session_id = datetime.now().strftime("%d-%m-%Y_%H-%M-%S-%f")

    # TCPDump start
    pcap = "pcap_" + str(session_id) + ".pcap"
    tcpdump = "tcpdump" \
              " -i " + config.interface + \
              " -n port " + str(port) + " or port " + str(port + 1) + " or port " + str(port + 2) + \
              " -w " + config.pcap_path + "/" + pcap
    pcap_capture_process = subprocess.Popen(tcpdump, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if DEBUG:
        pprint(tcpdump)
    time.sleep(2)

    # Censored Request
    censored, err = censorship_request(port, ip, domain)

    # TCPDump End
    time.sleep(10)
    pcap_capture_process.send_signal(subprocess.signal.SIGTERM)

    # Measurement Go app detected correct result from pcap
    go_censorship_result = detect_censorship_verify(session_id, config, pcap, port)

    if go_censorship_result == censored:
        return censored, err, session_id, True

    return censored, err, session_id, False


def build_go_measurement_app():
    process = subprocess.Popen("cd ../app && go build -o ../build/measurement -a .", shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    process.wait()
    if DEBUG:
        pprint("[Build Measurement] STDOUT: " + str(process.stdout.read()))
        pprint("[Build Measurement] STDERR: " + str(process.stderr.read()))
    if process.returncode != 0:
        print("Error building go measurement app. Terminating...")
        exit(1)


def detect_censorship_verify(session_id, config, pcap, local_port):
    pcap_filepath = config.pcap_path + "/" + pcap
    log_filepath = config.measurement_logs + "/" + session_id + ".log"

    go_execution = "../build/measurement --config_file resources/config_china_http.yml" + \
                   " --pcap " + pcap_filepath + \
                   " --bpf " + "\"tcp and port " + str(local_port) + "\"" + \
                   " --log-file \"" + log_filepath + "\""
    if DEBUG:
        pprint(go_execution)
    censorship_detect_app = subprocess.Popen(go_execution, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    censorship_detect_app.wait()
    time.sleep(2)

    with open(log_filepath, 'r') as fp:
        line = fp.readline()
        while line:
            if "Censorship Detected" in line:
                return True
            line = fp.readline()

    return False


def censorship_request(port, ip, domain):
    header = {
        'Host': domain
    }

    count = 0
    last_err = None

    while count < MAX_TRIES:
        s = requests.Session()
        s.mount('http://', SourcePortAdapter(port + count))
        #s.mount('https://', SourcePortAdapter(port + count))

        try:
            if DEBUG:
                pprint("Making request: " + str(ip) + "|" + str(port + count) + "|" + str(domain) + "|" + str(header))
            s.get("http://%s/" % ip, headers=header, timeout=5, allow_redirects=False)
        except requests.exceptions.ConnectionError as e:
            if e.__context__ is not None and e.__context__.__context__ is not None:
                if isinstance(e.__context__.__context__, ConnectionResetError):
                    if DEBUG:
                        pprint("Connection Reset")
                    # Censorship Detected
                    s.close()
                    return True, str(e.__context__.__context__)
            last_err = str(e)
        except Exception as e:
            last_err = str(e)

        if DEBUG:
            pprint("Request Error:" + last_err)

        time.sleep(1)
        count += 1
        s.close()
    return False, last_err


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

    parser.add_argument("input", help="Censorship Test Input File", action='store')
    parser.add_argument("interface", help="Interface to listen on to capture packets", action='store')
    parser.add_argument("results_file", help="Path to censorship results file", action='store')
    parser.add_argument("--pcap-path", default="pcaps", help="Path to pcaps", action='store')
    parser.add_argument("--measurement-logs", default="logs", help="Path to measurement logs", action='store')

    config = parser.parse_args()

    pprint(config)
    return config


if __name__ == '__main__':
    config = parse_args()
    detect_censorship(config)
