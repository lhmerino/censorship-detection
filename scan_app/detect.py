import requests
import json
import subprocess
from pprint import pprint
import argparse
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


def detect_censorship(config):
    ASN_IPs = get_subjects(config)

    count = 0
    result = {}
    for ASN in ASN_IPs:
        for data in ASN_IPs[ASN]:
            request = detect_censorship_one(config, data['IP'], data['Domain'])

            result[data['IP']] = {
                'IP': data['IP'],
                'Domain': data['Domain'],
                'ASN': ASN,
                'Censored': request,
                'Detected': request
            }
            pprint("[*] " + str(count))
            count += 1
            if count >= 20:
                break
        break

    with open(config.results_file, 'w') as outfile:
        json.dump(result, outfile, indent=4)


def get_subjects(config):
    with open(config.censorship) as file:
        contents = json.load(file)
        return contents


def detect_censorship_one(config, ip, domain):
    s = requests.Session()
    port = random.uniform(1025, 65534)
    s.mount('http://', SourcePortAdapter(port))
    s.mount('https://', SourcePortAdapter(port))

    pcap_capture_process = subprocess.Popen("tcpdump -i " + config.interface + " -n port " + port + "' -w pcap",
                                            shell=True)

    censorship_request(ip, domain)

    subprocess.Popen.kill(pcap_capture_process)

    #censorship_detect_app = subprocess.Popen("")


def censorship_request(ip, domain):
    header = {
        'Host': domain
    }

    try:
        requests.get("http://%s/" % ip, headers=header,
                     timeout=5)
    except ConnectionResetError:
        # Censorship Detected
        return True
    except Exception:
        return False

    return True


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

    parser.add_argument("input-file", help="Censorship Test Input File", action='store')
    parser.add_argument("interface", help="Interface to listen on to capture packets", action='store')
    parser.add_argument("--pcap-file", help="Path to pcap results file", action='store')
    parser.add_argument("--results-file", help="Path to censorship results file", action='store')

    config = parser.parse_args()
    return config


if __name__ == '__main__':
    config = parse_args()
    detect_censorship(config)
