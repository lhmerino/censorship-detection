import json
from pprint import pprint
from scapy.all import rdpcap
from scapy.layers.dns import TCP
import collections

class Analyze:
    def __init__(self, pcap_file=None, results_file=None):

        if results_file is not None:
            self.results = self.load_json(results_file)
            self.checkMatch()

        if pcap_file is not None:
            self.pcap(pcap_file)

    def checkMatch(self):
        """
        Checks to make sure that GoMatch is True
        :return:
        """
        for IP in self.results:
            for run in self.results[IP]['Results']:
                if run['GoMatch'] is False:
                    pprint(run)

    def pcap(self, pcap_file):
        packets = rdpcap(pcap_file)

        packet_count = 0
        connections = {}
        for packet in packets:
            if packet.haslayer(TCP):  # For sanity reasons
                packet_count += 1

                if packet[TCP].dport != 80:
                    # Disregard packets back to client and only consider HTTP for now
                    continue

                src_port = packet[TCP].sport

                if src_port not in connections:
                    connections[src_port] = {}

                flags = str(packet[TCP].flags)

                if flags not in connections[src_port]:
                    connections[src_port][flags] = 1
                else:
                    connections[src_port][flags] += 1

        # Finished extracting flags from each connection, summarize it now
        summary = {}
        for src_port in connections:
            key = ''
            for flag in sorted(connections[src_port].keys()):
                key += str(flag) + ":" + str(connections[src_port][flag]) + "_"

            if key not in summary:
                summary[key] = [src_port]
            else:
                summary[key].append(src_port)

        #summary = sorted(summary.items(), key=lambda x: x[1], reverse=True)
        pprint(connections)
        pprint(len(connections))
        pprint(summary)
        # flags = {}
        # for connection in connections:
        #     for flag in


    @staticmethod
    def load_json(results_file):
        with open(results_file) as json_file:
            return json.load(json_file)


if __name__ == '__main__':
    Analyze('../testdata/tripwire-1597963966.pcap')