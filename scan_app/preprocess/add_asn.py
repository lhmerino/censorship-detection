import pyasn
import csv

from pprint import pprint

def main():
    # Initialize ASNDB
    asndb = pyasn.pyasn('../ipasn.gz')

    with open('../resources/results_blocked_ip_site_country_asn.csv', mode='w') as csv_file:
        headers = ['IP', 'Domain', 'Country', 'ASN']
        writer = csv.DictWriter(csv_file, fieldnames=headers, extrasaction='ignore')

        with open('../resources/results_blocked_ip_site_country.csv', 'r') as file:
            reader = csv.reader(file, delimiter=",")
            for i, pieces in enumerate(reader):
                block = {'IP': pieces[0], 'Domain': pieces[1], 'Country': pieces[2],
                             'ASN': asndb.lookup(pieces[0])[0]}
                writer.writerow(block)

if __name__ == '__main__':
    main()

