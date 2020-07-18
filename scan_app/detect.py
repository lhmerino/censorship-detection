import requests
import json
import subprocess
from pprint import pprint
import argparse
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import uuid
import time

MAX_TRIES = 3
# python detect.py resources/test.json en0 results/censorship_result.json
# Censored: curl -H "Host: groups.google.com" 120.77.156.227
# Censored: curl -H "Host: google.com.sa" 114.55.249.66

def detect_censorship(config):
    ASN_IPs = get_subjects(config)
    build_go_measurement_app()

    count = 0
    result = {}
    for ASN in ASN_IPs:
        for data in ASN_IPs[ASN]:
            pprint("[Scan App] IP:" + data['IP'] + "-Domain: " +data['Domain'])
            censored, pcap = detect_censorship_one(config, data['IP'], data['Domain'])

            result[data['IP']] = {
                'IP': data['IP'],
                'Domain': data['Domain'],
                'ASN': ASN,
                'Censored': censored,
                'PCAP': pcap
            }
            pprint("[*] " + str(count))
            count += 1
            if count >= 20:
                break
        break

    with open(config.results_file, 'w') as outfile:
        json.dump(result, outfile, indent=4)


def get_subjects(config):
    with open(config.input) as file:
        contents = json.load(file)
        return contents


def detect_censorship_one(config, ip, domain):
    # Choose random local port
    session = requests.Session()
    port = int(random.uniform(1025, 65534))
    session.mount('http://', SourcePortAdapter(port))
    session.mount('https://', SourcePortAdapter(port))

    # TCPDump start
    pcap = "pcap_" + str(uuid.uuid1().int) + ".pcap"
    tcpdump = "tcpdump -i " + config.interface + " -n port " + str(port) + " -w " + config.pcap_path + "/" + pcap
    pcap_capture_process = subprocess.Popen(tcpdump, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pprint(tcpdump)
    time.sleep(3)

    # Censored Request
    censored = censorship_request(session, ip, domain)

    # TCPDump End
    time.sleep(10)
    pcap_capture_process.send_signal(subprocess.signal.SIGTERM)

    # Measurement Go app detected correct result from pcap
    detect_censorship_verify(config, pcap, port)

    return censored, pcap


def build_go_measurement_app():
    process = subprocess.Popen("cd ../app && go build -o ../build/measurement -a .", shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    process.wait()
    pprint("[Build Measurement] STDOUT: " + str(process.stdout.read()))
    pprint("[Build Measurement] STDERR: " + str(process.stderr.read()))
    if process.returncode != 0:
        print("Error building go measurement app. Terminating...")
        exit(1)

def detect_censorship_verify(config, pcap, local_port):
    pcap_filepath = config.pcap_path + "/" + pcap
    log_filepath = config.measurement_logs + "/" + pcap.split('_')[1].split('.')[0] + ".log"
    pprint("../build/measurement --config_file resources/config_china_http.yml --pcap " + pcap_filepath + " --port " +
           str(local_port) + " --log-file \"" + log_filepath + "\"")
    censorship_detect_app = subprocess.Popen("../build/measurement --config_file resources/config_china_http.yml "
                                             "--pcap " + pcap_filepath + " --port " + str(local_port) + " --log-file \""
                                             + log_filepath + "\"", shell=True, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)

    censorship_detect_app.wait()
    time.sleep(2)
    pprint("[Go Measurement App] stdout: " + str(censorship_detect_app.stdout.read()))
    pprint("[Go Measurement App] stderr: " + str(censorship_detect_app.stderr.read()))
    with open(log_filepath, 'r') as fin:
        print("[Go Measurement App]: " + fin.read())


def censorship_request(session, ip, domain):
    header = {
        'Host': domain
    }

    count = 0

    while count < MAX_TRIES:
        try:
            session.get("http://%s/" % ip, headers=header, timeout=5)
        except ConnectionResetError:
            # Censorship Detected
            return True
        except Exception:
            count += 1

    return False


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
