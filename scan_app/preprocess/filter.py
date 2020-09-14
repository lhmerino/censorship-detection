import csv
import json
from pprint import pprint

def main():
    """
    Group the IP addresses by ASN numbers and write the output in JSON format.
    """
    ASN = {}

    with open('../resources/results_blocked_ip_site_country_asn.csv', mode='r') as csv_file:
        headers = ['IP', 'Domain', 'Country', 'ASN']
        reader = csv.reader(csv_file, delimiter=",")

        for i, row in enumerate(reader):
            data = dict(zip(headers, row))
            if data['Country'] != 'China':
                continue

            if data['ASN'] not in ASN:
                ASN[data['ASN']] = []

            ASN[data['ASN']].append({'IP': data['IP'], 'Domain': data['Domain']})

    with open('China_ASNs', 'w') as outfile:
        json.dump(ASN, outfile, indent=4)


if __name__ == '__main__':
    main()