import requests
import json
from scapy.all import *
from scapy.layers.dns import IP
#from threading import Thread
import subprocess
from pprint import pprint
import argparse
parser = argparse.ArgumentParser()
parser.parse_args()

Subjects_File = 'resources/China_ASN_IP.json'
PCAP_File = 'pcap_file'
Results_File = 'results/censored_requests_results.json'
Interface = 'en0'


def main():
    ASN_IPs = get_subjects()

    # PCAP capture
    # pcap_capture = Capture(Interface)
    # pcap_capture.start()
    #
    # time.sleep(5.0)

    pcap_capture = subprocess.run("tcpdump -i " + Interface + " -w pcap")

    count = 0
    result = {}
    for ASN in ASN_IPs:
        for data in ASN_IPs[ASN]:
            result[data['IP']] = {
                'IP': data['IP'],
                'Domain': data['Domain'],
                'ASN': ASN,
                'Censored': censorship_request(data['IP'], data['Domain'])
            }
            pprint("[*] " + str(count))
            count += 1
            if count >= 20:
                break
        break

    with open(Results_File, 'w') as outfile:
        json.dump(result, outfile, indent=4)



    # pcap_capture.join(2.0)
    #
    # if pcap_capture.is_alive():
    #     pcap_capture.socket.close()


def get_subjects():
    with open(Subjects_File) as file:
        contents = json.load(file)
        return contents


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

# Code adapted from https://blog.skyplabs.net/2018/03/01/python-sniffing-inside-a-thread-with-scapy/
# class Capture(Thread):
#     def __init__(self, interface):
#         super().__init__()
#         self.interface = interface
#         self.daemon = True
#         self.socket = None
#         self.stop_sniffer = Event()
#
#     def run(self):
#         pprint("Running")
#         self.socket = conf.L2listen(
#             type=ETH_P_ALL,
#             iface=self.interface,
#             filter="ip"
#         )
#
#         sniff(
#             opened_socket=self.socket,
#             prn=self.store_packet,
#             stop_filter=self.should_stop_sniffer
#         )
#
#     def store_packet(self, pkt):
#         ip_layer = pkt.getlayer(IP)
#         print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))
#         wrpcap(PCAP_File, pkt, append=True)
#
#     def should_stop_sniffer(self, pkt):
#         return self.stop_sniffer.isSet()
#
#     def join(self, timeout=None):
#         self.stop_sniffer.set()
#         super().join(timeout)

def parseFlags():
    pass


if __name__ == '__main__':
    parseFlags()
    main()